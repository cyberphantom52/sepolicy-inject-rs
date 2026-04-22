use clap::{Args, Parser, Subcommand, ValueEnum};
use sepolicy::parser::ast::Policy;
use sepolicy::{CilPolicy, SePolicy, log, parser};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tracing::{debug, error, info};

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

fn main() -> ExitCode {
    log::init_subscriber();

    let cli = Cli::parse();

    match cli.source {
        Source::Cil(cil_source) => match cil_source {
            CilSourceCommand::Cil { source, command } => match command {
                Some(SingleCilCommand::Compile(cmd)) => {
                    let Ok(mut policy) = CilPolicy::compile_split(std::iter::once(source)) else {
                        error!("Failed to compile CIL policy");
                        return ExitCode::FAILURE;
                    };

                    handle_cil_compile_command(Some(cmd), &mut policy)
                }
                Some(SingleCilCommand::Shared(cmd)) => handle_single_cil_command(&source, cmd),
                None => {
                    let Ok(mut policy) = CilPolicy::compile_split(std::iter::once(source)) else {
                        error!("Failed to compile CIL policy");
                        return ExitCode::FAILURE;
                    };

                    handle_cil_compile_command(None, &mut policy)
                }
            },

            CilSourceCommand::SplitCil { source, command } => {
                let Ok(mut policy) = CilPolicy::compile_split(source.iter()) else {
                    error!("Failed to compile split CIL policy");
                    return ExitCode::FAILURE;
                };

                handle_cil_compile_command(command, &mut policy)
            }
        },

        Source::Precompiled { policy, command } => {
            let Some(mut policy) = SePolicy::from_file(policy) else {
                error!("Failed to load precompiled policy");
                return ExitCode::FAILURE;
            };
            handle_sepol_command(command, &mut policy)
        }

        #[cfg(target_os = "android")]
        Source::LoadSplit { command } => {
            let Some(mut policy) = SePolicy::from_split() else {
                error!("Failed to load split policy");
                return ExitCode::FAILURE;
            };
            handle_sepol_command(command, &mut policy)
        }

        #[cfg(target_os = "android")]
        Source::LiveLoad { command } => {
            let Some(mut policy) = SePolicy::from_file("/sys/fs/selinux/policy") else {
                error!("Failed to load live policy");
                return ExitCode::FAILURE;
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
        if !policy.write(&out_path.to_string_lossy()) {
            error!(path = %out_path.display(), "Failed to write compiled policy");
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
                if !sepolicy.write(&file.to_string_lossy()) {
                    error!(path = %file.display(), "Failed to write patched policy");
                    return ExitCode::FAILURE;
                }
                info!(path = %file.display(), "Wrote patched policy to file");
            }

            #[cfg(target_os = "android")]
            if destination.live_patch {
                if !sepolicy.write("/sys/fs/selinux/load") {
                    error!("Failed to load patched policy into kernel");
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
) -> Result<CilPolicy, String>
where
    I: IntoIterator<Item = &'a Path>,
{
    let mut cil_policy = CilPolicy::from_files(files).map_err(|e| {
        error!(error = %e, "Failed to load CIL file(s)");
        format!("Failed to load CIL file(s): {}", e)
    })?;

    for te_path in policies {
        let policy = prepare_patch(te_path, macros)?;

        cil_policy = cil_policy.add_policy(&policy).map_err(|e| {
            error!(path = %te_path.display(), error = %e, "Failed to translate patch policy into CIL");
            format!("Failed to translate patch policy into CIL: {}", e)
        })?;
    }

    Ok(cil_policy)
}

fn prepare_cil_patch(
    source: &Path,
    policies: &[PathBuf],
    macros: &[PathBuf],
) -> Result<CilPolicy, String> {
    prepare_cil_patch_from_files(std::iter::once(source), policies, macros)
}

fn validate_cil_patch(
    source: &Path,
    resolve_with: &[PathBuf],
    policies: &[PathBuf],
    macros: &[PathBuf],
) -> Result<(), String> {
    let mut cil_policy = prepare_cil_patch_from_files(
        resolve_with
            .iter()
            .map(PathBuf::as_path)
            .chain(std::iter::once(source)),
        policies,
        macros,
    )?;

    cil_policy.validate().map_err(|e| {
        error!(path = %source.display(), error = %e, "Failed to resolve patched CIL policy");
        format!("Failed to resolve patched CIL policy: {}", e)
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

                let Ok(policy) = cil_policy.compile() else {
                    error!("Failed to compile patched CIL policy");
                    return ExitCode::FAILURE;
                };

                if !policy.write("/sys/fs/selinux/load") {
                    error!("Failed to load patched CIL policy into kernel");
                    return ExitCode::FAILURE;
                }
                info!("Successfully loaded patched CIL policy into kernel");
            }

            info!(count = policies.len(), "Successfully patched CIL policy");
        }
    }

    ExitCode::SUCCESS
}

pub fn prepare_patch<P, I>(path: P, macros: I) -> Result<Policy, String>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    use m4rs::processor::{Expander, MacroRegistry};

    let path_display = path.as_ref().display().to_string();

    let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
        error!(path = %path_display, error = %e, "Failed to read file");
        format!("Failed to read file: {}", e)
    })?;

    // Load macro definitions
    let mut registry = MacroRegistry::new();
    for macro_path in macros {
        let macro_path_str = macro_path
            .as_ref()
            .to_str()
            .ok_or("Macro path contains invalid UTF-8")?;
        debug!(macro_path = %macro_path_str, "Loading macro file");
        registry.load_file(macro_path_str).map_err(|e| {
            error!(macro_path = %macro_path_str, error = %e, "Failed to load macro file");
            format!("Failed to load macro file: {}", e)
        })?;
    }

    // Expand macros
    let mut expander = Expander::new(registry);
    let expanded = expander.expand(&content).map_err(|e| {
        error!(path = %path_display, error = %e, "M4 expansion failed");
        format!("M4 expansion failed: {}", e)
    })?;

    parser::parse(&expanded).map_err(|e| {
        error!(path = %path_display, error = %e, "Parse error");
        format!("Parse error: {}", e)
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
