use clap::{Args, Parser, Subcommand, ValueEnum};
use sepolicy::parser::ast::Policy;
use sepolicy::{CilPolicy, SePolicy, parser};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tracing::{error, info};

#[derive(Subcommand)]
enum Source {
    #[command(flatten)]
    Cil(CilSourceCommand),
    Precompiled {
        #[arg(long, value_name = "FILE")]
        policy: PathBuf,

        #[command(subcommand)]
        command: Option<SepolCommand>,
    },

    #[cfg(target_os = "android")]
    LoadSplit {
        #[command(subcommand)]
        command: Option<SepolCommand>,
    },

    #[cfg(target_os = "android")]
    LiveLoad {
        #[command(subcommand)]
        command: Option<SepolCommand>,
    },
}

#[derive(Subcommand)]
enum CilSourceCommand {
    Cil {
        #[arg(value_name = ".cil")]
        source: PathBuf,

        #[command(subcommand)]
        command: Option<SingleCilCommand>,
    },

    SplitCil {
        #[arg(
            long,
            value_name = ".cil",
            num_args = 1,
            action = clap::ArgAction::Append
        )]
        source: Vec<PathBuf>,

        #[command(subcommand)]
        command: Option<CilCompileCommand>,
    },
}

#[derive(Subcommand)]
enum CilCompileCommand {
    /// Compile CIL into a binary policy, then optionally act on it
    Compile {
        /// Optionally save the compiled binary policy to disk
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,

        #[command(subcommand)]
        command: Option<SepolCommand>,
    },
}

#[derive(Subcommand)]
enum SingleCilCommand {
    #[command(flatten)]
    Compile(CilCompileCommand),

    #[command(flatten)]
    Shared(Commands),
}

#[derive(Subcommand)]
enum SepolCommand {
    /// Print rules from the sepolicy
    Print {
        /// Type of rules to print
        #[arg(value_enum, default_value_t = RuleType::All)]
        rule_type: RuleType,
    },

    #[command(flatten)]
    Shared(Commands),
}

#[derive(Subcommand)]
enum Commands {
    /// Patch the policy with rules from .te files
    Patch {
        /// .te file to apply (can be specified multiple times)
        #[arg(long = "policy", short = 'p', required = true, value_name = ".te")]
        policies: Vec<PathBuf>,

        /// M4 macro definition file (can be specified multiple times)
        #[arg(long = "macro", short = 'm', value_name = ".m4")]
        macros: Vec<PathBuf>,

        /// Additional CIL files to load before the patched source when resolving references
        #[arg(
            long = "resolve-with",
            value_name = ".cil",
            num_args = 1,
            action = clap::ArgAction::Append
        )]
        resolve_with: Vec<PathBuf>,

        #[command(flatten)]
        destination: Destination,
    },
}

#[derive(Args)]
struct Destination {
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,

    #[cfg(target_os = "android")]
    #[arg(long)]
    live_patch: bool,
}

/// SELinux Policy Injection Tool
#[derive(Parser)]
#[command(name = "sepolicy-inject-rs")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    source: Source,
}

#[derive(Clone, ValueEnum)]
enum RuleType {
    /// Print all rules
    All,
    /// Print only attributes
    Attributes,
    /// Print only types
    Types,
    /// Print only access vector tables (allow/deny rules)
    Avtabs,
    /// Print only type transitions
    Transitions,
    /// Print only genfs contexts
    Genfs,
}

/// Initialize the tracing subscriber based on the target platform.
///
/// On Android (when compiled with `--features android`), this uses `tracing-android`
/// to output logs to logcat.
///
/// On other platforms, this uses `tracing-subscriber` with an environment filter
/// (controllable via the `RUST_LOG` environment variable).
fn init_subscriber() {
    use tracing_subscriber::{prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    #[cfg(feature = "android")]
    {
        let android_layer = tracing_android::layer("sepolicy-inject-rs")
            .expect("Failed to create Android tracing layer");

        tracing_subscriber::registry()
            .with(filter)
            .with(android_layer)
            .init();
    }

    #[cfg(not(feature = "android"))]
    {
        use tracing_subscriber::fmt;

        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(true))
            .init();
    }
}

fn main() -> ExitCode {
    init_subscriber();

    let cli = Cli::parse();

    match cli.source {
        Source::Cil(cil_source) => match cil_source {
            CilSourceCommand::Cil { source, command } => match command {
                Some(SingleCilCommand::Compile(cmd)) => {
                    let mut policy = match CilPolicy::compile_split(std::iter::once(source)) {
                        Ok(policy) => policy,
                        Err(e) => {
                            error!(error = %e, "Failed to compile CIL policy");
                            return ExitCode::FAILURE;
                        }
                    };

                    handle_cil_compile_command(Some(cmd), &mut policy)
                }
                Some(SingleCilCommand::Shared(cmd)) => handle_single_cil_command(&source, cmd),
                None => {
                    let mut policy = match CilPolicy::compile_split(std::iter::once(source)) {
                        Ok(policy) => policy,
                        Err(e) => {
                            error!(error = %e, "Failed to compile CIL policy");
                            return ExitCode::FAILURE;
                        }
                    };

                    handle_cil_compile_command(None, &mut policy)
                }
            },

            CilSourceCommand::SplitCil { source, command } => {
                let mut policy = match CilPolicy::compile_split(source.iter()) {
                    Ok(policy) => policy,
                    Err(e) => {
                        error!(error = %e, "Failed to compile split CIL policy");
                        return ExitCode::FAILURE;
                    }
                };

                handle_cil_compile_command(command, &mut policy)
            }
        },

        Source::Precompiled { policy, command } => {
            let mut policy = match SePolicy::from_file(policy) {
                Ok(policy) => policy,
                Err(e) => {
                    error!(error = %e, "Failed to load precompiled policy");
                    return ExitCode::FAILURE;
                }
            };
            handle_sepol_command(command, &mut policy)
        }

        #[cfg(target_os = "android")]
        Source::LoadSplit { command } => {
            let mut policy = match SePolicy::from_split() {
                Ok(policy) => policy,
                Err(e) => {
                    error!(error = %e, "Failed to load split policy");
                    return ExitCode::FAILURE;
                }
            };
            handle_sepol_command(command, &mut policy)
        }

        #[cfg(target_os = "android")]
        Source::LiveLoad { command } => {
            let mut policy = match SePolicy::from_file("/sys/fs/selinux/policy") {
                Ok(policy) => policy,
                Err(e) => {
                    error!(error = %e, "Failed to load live policy");
                    return ExitCode::FAILURE;
                }
            };
            handle_sepol_command(command, &mut policy)
        }
    }
}

fn handle_cil_compile_command(
    command: Option<CilCompileCommand>,
    policy: &mut SePolicy,
) -> ExitCode {
    // default: compile with no output, no further command
    let (output, inner_command) = match command {
        Some(CilCompileCommand::Compile { output, command }) => (output, command),
        None => (None, None),
    };

    if let Some(out_path) = output {
        if let Err(e) = policy.write(&out_path) {
            error!(path = %out_path.display(), error = %e, "Failed to write compiled policy");
            return ExitCode::FAILURE;
        }
        info!(path = %out_path.display(), "Wrote compiled policy to file");
    }

    handle_sepol_command(inner_command, policy)
}

fn handle_sepol_command(command: Option<SepolCommand>, policy: &mut SePolicy) -> ExitCode {
    match command {
        Some(SepolCommand::Print { rule_type }) => {
            let rules = match rule_type {
                RuleType::All => policy.rules(),
                RuleType::Attributes => policy.attributes(),
                RuleType::Types => policy.types(),
                RuleType::Avtabs => policy.avtabs(),
                RuleType::Transitions => policy.transitions(),
                RuleType::Genfs => policy.genfs_contexts(),
            };
            for rule in rules {
                println!("{}", rule);
            }
        }

        Some(SepolCommand::Shared(cmd)) => return handle_command(cmd, policy),

        None => print_summary(policy),
    }

    ExitCode::SUCCESS
}

fn handle_command(command: Commands, sepolicy: &mut SePolicy) -> ExitCode {
    match command {
        Commands::Patch {
            policies,
            macros,
            resolve_with: _,
            destination,
        } => {
            for te_path in &policies {
                let Ok(policy) = prepare_patch(te_path, &macros) else {
                    return ExitCode::FAILURE;
                };
                sepolicy.apply_policy(&policy);
            }
            info!(count = policies.len(), "Successfully patched policy");

            if let Some(file) = destination.output {
                if let Err(e) = sepolicy.write(&file) {
                    error!(path = %file.display(), error = %e, "Failed to write patched policy");
                    return ExitCode::FAILURE;
                }
                info!(path = %file.display(), "Wrote patched policy to file");
            }

            #[cfg(target_os = "android")]
            if destination.live_patch {
                if let Err(e) = sepolicy.write("/sys/fs/selinux/load") {
                    error!(error = %e, "Failed to load patched policy into kernel");
                    return ExitCode::FAILURE;
                }
                info!("Successfully loaded patched policy into kernel");
            }
        }
    }

    ExitCode::SUCCESS
}

fn prepare_cil_patch_from_files<'a, I>(
    files: I,
    policies: &[PathBuf],
    macros: &[PathBuf],
) -> sepolicy::Result<CilPolicy>
where
    I: IntoIterator<Item = &'a Path>,
{
    let mut cil_policy = CilPolicy::from_files(files).inspect_err(|e| {
        error!(error = %e, "Failed to load CIL file(s)");
    })?;

    for te_path in policies {
        let policy = prepare_patch(te_path, macros)?;

        cil_policy = cil_policy.add_policy(&policy).inspect_err(|e| {
            error!(path = %te_path.display(), error = %e, "Failed to translate patch policy into CIL");
        })?;
    }

    Ok(cil_policy)
}

fn prepare_cil_patch(
    source: &Path,
    policies: &[PathBuf],
    macros: &[PathBuf],
) -> sepolicy::Result<CilPolicy> {
    prepare_cil_patch_from_files(std::iter::once(source), policies, macros)
}

fn validate_cil_patch(
    source: &Path,
    resolve_with: &[PathBuf],
    policies: &[PathBuf],
    macros: &[PathBuf],
) -> sepolicy::Result<()> {
    let mut cil_policy = prepare_cil_patch_from_files(
        resolve_with
            .iter()
            .map(PathBuf::as_path)
            .chain(std::iter::once(source)),
        policies,
        macros,
    )?;

    cil_policy.validate().inspect_err(|e| {
        error!(path = %source.display(), error = %e, "Failed to resolve patched CIL policy");
    })
}

fn handle_single_cil_command(source: &Path, command: Commands) -> ExitCode {
    match command {
        Commands::Patch {
            policies,
            macros,
            resolve_with,
            destination,
        } => {
            let Destination {
                output,
                #[cfg(target_os = "android")]
                live_patch,
            } = destination;

            let needs_output = output.is_some();

            #[cfg(target_os = "android")]
            let needs_live_patch = live_patch;
            #[cfg(not(target_os = "android"))]
            let needs_live_patch = false;

            if validate_cil_patch(source, &resolve_with, &policies, &macros).is_err() {
                return ExitCode::FAILURE;
            }

            if !needs_output && !needs_live_patch {
                info!(count = policies.len(), "Successfully patched CIL policy");
                return ExitCode::SUCCESS;
            }

            if let Some(file) = output {
                let Ok(mut cil_policy) = prepare_cil_patch(source, &policies, &macros) else {
                    return ExitCode::FAILURE;
                };

                if let Err(err) = cil_policy.write(&file) {
                    error!(path = %file.display(), error = %err, "Failed to write patched CIL policy");
                    return ExitCode::FAILURE;
                }
                info!(path = %file.display(), "Wrote patched CIL policy to file");
            }

            #[cfg(target_os = "android")]
            if live_patch {
                let Ok(mut cil_policy) = prepare_cil_patch(source, &policies, &macros) else {
                    return ExitCode::FAILURE;
                };

                let policy = match cil_policy.compile() {
                    Ok(policy) => policy,
                    Err(e) => {
                        error!(error = %e, "Failed to compile patched CIL policy");
                        return ExitCode::FAILURE;
                    }
                };

                if let Err(e) = policy.write("/sys/fs/selinux/load") {
                    error!(error = %e, "Failed to load patched CIL policy into kernel");
                    return ExitCode::FAILURE;
                }
                info!("Successfully loaded patched CIL policy into kernel");
            }

            info!(count = policies.len(), "Successfully patched CIL policy");
        }
    }

    ExitCode::SUCCESS
}

fn prepare_patch(path: &Path, macros: &[PathBuf]) -> sepolicy::Result<Policy> {
    parser::parse_file(path, macros).inspect_err(|e| {
        error!(path = %path.display(), error = %e, "Failed to prepare patch");
    })
}

fn print_summary(policy: &mut SePolicy) {
    println!("Policy loaded successfully!");
    println!("  Attributes:     {}", policy.attributes().len());
    println!("  Types:          {}", policy.types().len());
    println!("  AV Rules:       {}", policy.avtabs().len());
    println!("  Transitions:    {}", policy.transitions().len());
    println!("  Genfs Contexts: {}", policy.genfs_contexts().len());
    println!();
    println!("Use 'print' subcommand to display rules.");
    println!("Use 'patch' subcommand to apply .te files.");
}
