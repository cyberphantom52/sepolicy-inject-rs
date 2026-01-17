use clap::{Args, Parser, Subcommand, ValueEnum};
use sepolicy::{CilPolicy, SePolicy, log};
use std::path::PathBuf;
use std::process::ExitCode;
use tracing::{error, info};

/// Source of the SELinux policy
#[derive(Args)]
#[group(id = "source", required = true, multiple = false)]
struct SourceArgs {
    /// Load monolithic sepolicy from a precompiled file
    #[arg(long)]
    precompiled: Option<PathBuf>,

    /// Load monolithic sepolicy from a CIL file
    #[arg(long)]
    cil: Option<PathBuf>,

    /// Load from live policy (Android only)
    #[cfg(target_os = "android")]
    #[arg(long)]
    live_load: bool,

    /// Load from precompiled sepolicy or compile split cil policies (Android only)
    #[cfg(target_os = "android")]
    #[arg(long)]
    load_split: bool,

    /// Compile split cil policies (Android only)
    #[cfg(target_os = "android")]
    #[arg(long)]
    compile_split: bool,
}

/// Output format for patched policy
#[derive(Clone, ValueEnum, Default)]
enum OutputFormat {
    /// Binary policy file
    #[default]
    Binary,
    /// CIL text file
    Cil,
}

/// Output destination for patched policy
#[derive(Args)]
struct OutputArgs {
    /// Output file path
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,

    /// Output format (required when --output is specified)
    #[arg(long, value_enum, default_value_t = OutputFormat::Binary)]
    format: OutputFormat,

    /// Load patched policy directly into kernel (Android only)
    #[cfg(target_os = "android")]
    #[arg(long, conflicts_with_all = ["output", "format"])]
    live_patch: bool,
}

/// SELinux Policy Injection Tool
#[derive(Parser)]
#[command(name = "sepolicy-inject-rs")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    source: SourceArgs,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Print rules from the loaded sepolicy
    Print {
        /// Type of rules to print
        #[arg(value_enum, default_value_t = RuleType::All)]
        rule_type: RuleType,
    },

    /// Patch the policy with rules from .te files
    Patch {
        /// .te file(s) to apply (can be specified multiple times)
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,

        /// M4 macro definition file (can be specified multiple times)
        #[arg(long = "macro", short = 'm', value_name = "FILE")]
        macros: Vec<PathBuf>,

        #[command(flatten)]
        output_args: OutputArgs,
    },
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
    // Initialize tracing subscriber
    log::init_subscriber();

    let cli = Cli::parse();

    // Check if CIL source is used
    if let Some(cil_path) = &cli.source.cil {
        return handle_cil_source(cil_path, &cli);
    }

    // Handle binary policy source
    let sepolicy = if let Some(path) = &cli.source.precompiled {
        SePolicy::from_file(path)
    } else {
        #[cfg(target_os = "android")]
        {
            if cli.source.live_load {
                SePolicy::from_file("/sys/fs/selinux/policy")
            } else if cli.source.load_split {
                SePolicy::from_split()
            } else if cli.source.compile_split {
                SePolicy::compile_split()
            } else {
                SePolicy::from_file("/sys/fs/selinux/policy")
            }
        }
        #[cfg(not(target_os = "android"))]
        {
            unreachable!("Source group is required")
        }
    };

    let mut sepolicy = match sepolicy {
        Some(s) => s,
        None => {
            error!("Cannot load policy");
            return ExitCode::FAILURE;
        }
    };

    // Handle commands for binary policy
    match cli.command {
        Some(Commands::Print { rule_type }) => {
            let rules = match rule_type {
                RuleType::All => sepolicy.rules(),
                RuleType::Attributes => sepolicy.attributes(),
                RuleType::Types => sepolicy.types(),
                RuleType::Avtabs => sepolicy.avtabs(),
                RuleType::Transitions => sepolicy.transitions(),
                RuleType::Genfs => sepolicy.genfs_contexts(),
            };

            for rule in rules {
                println!("{}", rule);
            }
        }
        Some(Commands::Patch {
            files,
            macros,
            output_args,
        }) => {
            for te_path in &files {
                if let Err(e) = sepolicy.load_rules_from_file(te_path, &macros) {
                    error!(path = %te_path.display(), error = %e, "Error applying policy file");
                    return ExitCode::FAILURE;
                }
            }
            info!(count = files.len(), "Successfully patched policy");

            // Save to output file if specified
            if let Some(out_path) = output_args.output {
                let path_str = out_path.to_string_lossy();
                match output_args.format {
                    OutputFormat::Binary => {
                        if !sepolicy.write(&path_str) {
                            error!(path = %path_str, "Failed to write policy to file");
                            return ExitCode::FAILURE;
                        }
                        info!(path = %path_str, "Wrote patched binary policy to file");
                    }
                    OutputFormat::Cil => {
                        error!("CIL output is only supported when loading from --cil source");
                        return ExitCode::FAILURE;
                    }
                }
            }

            // Live patch on Android
            #[cfg(target_os = "android")]
            if output_args.live_patch {
                if !sepolicy.write("/sys/fs/selinux/load") {
                    error!("Failed to load policy into kernel");
                    return ExitCode::FAILURE;
                }
                info!("Successfully loaded patched policy into kernel");
            }
        }
        None => {
            print_policy_info(&sepolicy);
        }
    }

    ExitCode::SUCCESS
}

/// Handle CIL source input
fn handle_cil_source(cil_path: &PathBuf, cli: &Cli) -> ExitCode {
    let mut cil_policy = match CilPolicy::from_file(cil_path) {
        Some(p) => p,
        None => {
            error!("Cannot load CIL policy");
            return ExitCode::FAILURE;
        }
    };

    match &cli.command {
        Some(Commands::Print { .. }) => {
            error!("Print command is not supported for CIL source. Use --precompiled instead.");
            return ExitCode::FAILURE;
        }
        Some(Commands::Patch {
            files,
            macros,
            output_args,
        }) => {
            // Patch CIL with TE files
            for te_path in files {
                if let Err(e) = cil_policy.load_rules_from_file(te_path, macros) {
                    error!(path = %te_path.display(), error = %e, "Error applying policy file");
                    return ExitCode::FAILURE;
                }
            }
            info!(count = files.len(), "Successfully patched CIL policy");

            // Write output
            if let Some(out_path) = &output_args.output {
                let path_str = out_path.to_string_lossy();
                match output_args.format {
                    OutputFormat::Cil => {
                        // For CIL output, write directly without compilation
                        if !cil_policy.write(&path_str) {
                            error!(path = %path_str, "Failed to write CIL to file");
                            return ExitCode::FAILURE;
                        }
                        info!(path = %path_str, "Wrote patched CIL policy to file");
                    }
                    OutputFormat::Binary => {
                        // Binary output requires compilation first
                        if !cil_policy.compile() {
                            error!("Failed to compile CIL policy");
                            return ExitCode::FAILURE;
                        }
                        error!("Binary output from CIL source is not yet supported");
                        return ExitCode::FAILURE;
                    }
                }
            }

            #[cfg(target_os = "android")]
            if output_args.live_patch {
                error!("Live patch is not supported for CIL source");
                return ExitCode::FAILURE;
            }
        }
        None => {
            info!("CIL policy loaded successfully. Use 'patch' subcommand to apply .te files.");
        }
    }

    ExitCode::SUCCESS
}

fn print_policy_info(sepolicy: &SePolicy) {
    let attrs = sepolicy.attributes();
    let types = sepolicy.types();
    let avtabs = sepolicy.avtabs();
    let transitions = sepolicy.transitions();
    let genfs = sepolicy.genfs_contexts();

    println!("Policy loaded successfully!");
    println!("  Attributes:     {}", attrs.len());
    println!("  Types:          {}", types.len());
    println!("  AV Rules:       {}", avtabs.len());
    println!("  Transitions:    {}", transitions.len());
    println!("  Genfs Contexts: {}", genfs.len());
    println!();
    println!("Use 'print' subcommand to display rules.");
    println!("Use 'patch' subcommand to apply .te files.");
}
