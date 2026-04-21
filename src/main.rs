use clap::{Args, Parser, Subcommand, ValueEnum};
use sepolicy::{CilPolicy, SePolicy, log};
use std::path::PathBuf;
use std::process::ExitCode;
use tracing::{error, info};

#[derive(Subcommand)]
enum Source {
    Cil {
        #[arg(
            long,
            value_name = "FILE",
            num_args = 1,
            action = clap::ArgAction::Append
        )]
        split: Vec<PathBuf>,

        #[command(subcommand)]
        command: Option<CilCommand>,
    },
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
enum CilCommand {
    /// Compile CIL into a binary policy, then optionally act on it
    Compile {
        /// Optionally save the compiled binary policy to disk
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,

        #[command(subcommand)]
        command: Option<SepolCommand>,
    },

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
        Source::Cil { split, command } => {
            let (output, inner_command) = match command {
                Some(CilCommand::Compile { output, command }) => (output, command),
                Some(CilCommand::Shared(_)) => {
                    error!("Direct CIL operations not implemented yet");
                    return ExitCode::FAILURE;
                }
                None => (None, None),
            };

            let Ok(mut policy) = CilPolicy::compile_split(split.iter()) else {
                error!("Failed to compile CIL policy");
                return ExitCode::FAILURE;
            };

            if let Some(out_path) = output {
                if !policy.write(&out_path.to_string_lossy()) {
                    error!(path = %out_path.display(), "Failed to write compiled policy");
                    return ExitCode::FAILURE;
                }
                info!(path = %out_path.display(), "Wrote compiled policy to file");
            }

            handle_sepol_command(inner_command, &mut policy)
        }

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
                error!("");
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

fn handle_command(command: Commands, policy: &mut SePolicy) -> ExitCode {
    match command {
        Commands::Patch {
            policies,
            macros,
            destination,
        } => {
            for te_path in &policies {
                if let Err(e) = policy.load_rules_from_file(te_path, &macros) {
                    error!(path = %te_path.display(), error = %e, "Error applying policy file");
                    return ExitCode::FAILURE;
                }
            }
            info!(count = policies.len(), "Successfully patched policy");

            if let Some(file) = destination.output {
                if !policy.write(&file.to_string_lossy()) {
                    error!(path = %file.display(), "Failed to write patched policy");
                    return ExitCode::FAILURE;
                }
                info!(path = %file.display(), "Wrote patched policy to file");
            }

            #[cfg(target_os = "android")]
            if destination.live_patch {
                if !policy.write("/sys/fs/selinux/load") {
                    error!("Failed to load patched policy into kernel");
                    return ExitCode::FAILURE;
                }
                info!("Successfully loaded patched policy into kernel");
            }
        }
    }

    ExitCode::SUCCESS
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
