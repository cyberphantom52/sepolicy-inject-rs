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

    /// Load monolithic sepolicy from a CIL file (compiled internally)
    #[arg(long)]
    cil: Option<PathBuf>,

    /// Load from live policy (Android only)
    #[cfg(target_os = "android")]
    #[arg(long)]
    live_load: bool,

    /// Load from precompiled split policy or compile split CIL policies (Android only)
    #[cfg(target_os = "android")]
    #[arg(long)]
    load_split: bool,

    /// Compile split CIL policies (Android only)
    #[cfg(target_os = "android")]
    #[arg(long)]
    compile_split: bool,
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

        /// Save patched policy to file
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,

        /// Load patched policy directly into kernel
        #[cfg(target_os = "android")]
        #[arg(long)]
        live_patch: bool,
    },

    /// Extract all CIL AST statements related to a label
    ///
    /// This subcommand requires `--cil`.
    Extract {
        /// SELinux label/type to extract from the input CIL
        #[arg(value_name = "LABEL")]
        label: String,
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

fn load_policy_from_source(source: &SourceArgs) -> Result<SePolicy, String> {
    if let Some(path) = &source.precompiled {
        return SePolicy::from_file(path)
            .ok_or_else(|| format!("failed to load precompiled policy: {}", path.display()));
    }

    if let Some(path) = &source.cil {
        info!(path = %path.display(), "Compiling policy from CIL file");
        return CilPolicy::compile_file(path)
            .map_err(|e| format!("failed to compile CIL file {}: {}", path.display(), e));
    }

    #[cfg(target_os = "android")]
    {
        if source.live_load {
            SePolicy::from_file("/sys/fs/selinux/policy")
                .ok_or_else(|| "failed to load live policy".to_string())
        } else if source.load_split {
            SePolicy::from_split().ok_or_else(|| "failed to load split policy".to_string())
        } else if source.compile_split {
            SePolicy::compile_split().ok_or_else(|| "failed to compile split policy".to_string())
        } else {
            Err("no policy source selected".to_string())
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        Err("no policy source selected".to_string())
    }
}

fn extract_from_cil_source(source: &SourceArgs, label: &str) -> Result<Vec<String>, String> {
    let path = source
        .cil
        .as_ref()
        .ok_or_else(|| "the 'extract' subcommand requires '--cil <FILE>'".to_string())?;

    info!(
        path = %path.display(),
        label = %label,
        "Extracting CIL statements for label"
    );

    CilPolicy::extract_label_from_file(path, label).map_err(|e| {
        format!(
            "failed to extract label '{}' from CIL file {}: {}",
            label,
            path.display(),
            e
        )
    })
}

fn print_cil_matches(matches: &[String]) {
    for (index, entry) in matches.iter().enumerate() {
        if index > 0 {
            println!();
        }
        println!("{entry}");
    }
}

fn main() -> ExitCode {
    // Initialize tracing subscriber
    log::init_subscriber();

    let cli = Cli::parse();

    // Handle extraction directly from CIL without compiling to policydb first.
    if let Some(Commands::Extract { label }) = &cli.command {
        let matches = match extract_from_cil_source(&cli.source, label) {
            Ok(matches) => matches,
            Err(e) => {
                error!(error = %e, "Failed to extract label from CIL source");
                return ExitCode::FAILURE;
            }
        };

        if matches.is_empty() {
            println!("No matching CIL statements found for '{}'.", label);
        } else {
            print_cil_matches(&matches);
        }

        return ExitCode::SUCCESS;
    }

    // Determine the source and load the policy
    let mut sepolicy = match load_policy_from_source(&cli.source) {
        Ok(policy) => policy,
        Err(e) => {
            error!(error = %e, "Cannot load policy");
            return ExitCode::FAILURE;
        }
    };

    // Handle commands
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
                println!("{rule}");
            }
        }
        Some(Commands::Patch {
            files,
            macros,
            output,
            #[cfg(target_os = "android")]
            live_patch,
        }) => {
            for te_path in &files {
                if let Err(e) = sepolicy.load_rules_from_file(te_path, &macros) {
                    error!(path = %te_path.display(), error = %e, "Error applying policy file");
                    return ExitCode::FAILURE;
                }
            }
            info!(count = files.len(), "Successfully patched policy");

            // Save to output file if specified
            if let Some(out_path) = output {
                let path_str = out_path.to_string_lossy();
                if !sepolicy.write(&path_str) {
                    error!(path = %path_str, "Failed to write policy to file");
                    return ExitCode::FAILURE;
                }
                info!(path = %path_str, "Wrote patched policy to file");
            }

            // Live patch on Android
            #[cfg(target_os = "android")]
            if live_patch {
                if !sepolicy.write("/sys/fs/selinux/load") {
                    error!("Failed to load policy into kernel");
                    return ExitCode::FAILURE;
                }
                info!("Successfully loaded patched policy into kernel");
            }
        }
        Some(Commands::Extract { .. }) => {
            unreachable!("extract is handled before loading the compiled policy")
        }
        None => {
            // No command specified, show basic info
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
            println!("Use 'extract <label>' with '--cil <FILE>' to query CIL statements.");
        }
    }

    ExitCode::SUCCESS
}
