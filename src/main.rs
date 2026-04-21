use clap::{Args, Parser, Subcommand, ValueEnum};
use sepolicy::{CilPolicy, CilSourcePolicy, SePolicy, log};
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

    /// Load policy from a CIL file. Patch operations edit the CIL source; other operations compile it internally.
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

    /// Compile split CIL policies. On non-Android, provide them explicitly with `--split-cil <FILE>`.
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

    /// Split CIL file(s) to compile when using `--compile-split`
    ///
    /// On non-Android targets, `--compile-split` requires at least one of these.
    #[arg(long = "split-cil", value_name = "FILE")]
    split_cils: Vec<PathBuf>,

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

        /// CIL mapping file(s) used to remap unsuffixed TE names to Android API-suffixed CIL names
        #[arg(long = "mapping", value_name = "FILE")]
        mappings: Vec<PathBuf>,

        /// Save patched policy to file
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,

        /// Load patched policy directly into kernel
        #[cfg(target_os = "android")]
        #[arg(long)]
        live_patch: bool,
    },

    /// Extract all CIL AST statements related to one or more labels
    ///
    /// This subcommand requires `--cil`.
    Extract {
        /// SELinux label/type(s) to extract from the input CIL
        #[arg(required = true, value_name = "LABEL")]
        labels: Vec<String>,
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

fn load_policy_from_source(
    source: &SourceArgs,
    split_cils: &[PathBuf],
) -> Result<SePolicy, String> {
    if let Some(path) = &source.precompiled {
        return SePolicy::from_file(path)
            .ok_or_else(|| format!("failed to load precompiled policy: {}", path.display()));
    }

    if let Some(path) = &source.cil {
        info!(path = %path.display(), "Compiling policy from CIL file");
        return CilPolicy::compile_file(path)
            .map_err(|e| format!("failed to compile CIL file {}: {}", path.display(), e));
    }

    if source.compile_split {
        if !split_cils.is_empty() {
            info!(
                count = split_cils.len(),
                "Compiling policy from manually specified split CIL files"
            );
            return CilPolicy::compile_files(split_cils.iter()).map_err(|e| {
                format!(
                    "failed to compile manually specified split CIL files: {}",
                    e
                )
            });
        }

        #[cfg(target_os = "android")]
        {
            return SePolicy::compile_split()
                .ok_or_else(|| "failed to compile split policy".to_string());
        }

        #[cfg(not(target_os = "android"))]
        {
            return Err(
                "on non-Android targets, '--compile-split' requires at least one '--split-cil <FILE>'"
                    .to_string(),
            );
        }
    }

    #[cfg(target_os = "android")]
    {
        if source.live_load {
            SePolicy::from_file("/sys/fs/selinux/policy")
                .ok_or_else(|| "failed to load live policy".to_string())
        } else if source.load_split {
            SePolicy::from_split().ok_or_else(|| "failed to load split policy".to_string())
        } else {
            Err("no policy source selected".to_string())
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        Err("no policy source selected".to_string())
    }
}

fn extract_from_cil_source(
    source: &SourceArgs,
    labels: &[String],
) -> Result<Vec<(String, Vec<String>)>, String> {
    let path = source
        .cil
        .as_ref()
        .ok_or_else(|| "the 'extract' subcommand requires '--cil <FILE>'".to_string())?;

    info!(
        path = %path.display(),
        count = labels.len(),
        "Extracting CIL statements for labels"
    );

    let mut policy = CilPolicy::from_file(path)
        .map_err(|e| format!("failed to load CIL file {}: {}", path.display(), e))?;

    let mut results = Vec::with_capacity(labels.len());

    for label in labels {
        let trimmed = label.trim();

        info!(
            path = %path.display(),
            label = %trimmed,
            "Extracting CIL statements for label"
        );

        let matches = policy.extract_label(trimmed).map_err(|e| {
            format!(
                "failed to extract label '{}' from CIL file {}: {}",
                trimmed,
                path.display(),
                e
            )
        })?;

        results.push((trimmed.to_string(), matches));
    }

    Ok(results)
}

fn print_cil_matches(matches: &[String]) {
    for (index, entry) in matches.iter().enumerate() {
        if index > 0 {
            println!();
        }
        println!("{entry}");
    }
}

fn print_cil_results(results: &[(String, Vec<String>)]) {
    let show_headers = results.len() > 1;

    for (index, (label, matches)) in results.iter().enumerate() {
        if index > 0 {
            println!();
        }

        if show_headers {
            println!("== {label} ==");
            println!();
        }

        if matches.is_empty() {
            println!("No matching CIL statements found for '{}'.", label);
        } else {
            print_cil_matches(matches);
        }
    }
}

fn patch_cil_source(
    source: &SourceArgs,
    files: &[PathBuf],
    macros: &[PathBuf],
    mappings: &[PathBuf],
    output: Option<&PathBuf>,
    #[cfg(target_os = "android")] live_patch: bool,
) -> Result<(), String> {
    let path = source
        .cil
        .as_ref()
        .ok_or_else(|| "the 'patch' subcommand requires '--cil <FILE>'".to_string())?;

    let out_path =
        output.ok_or_else(|| "patching a CIL source requires '--output <FILE>'".to_string())?;

    #[cfg(target_os = "android")]
    if live_patch {
        return Err(
            "live patching is not supported when using '--cil'; write the patched CIL to a file instead"
                .to_string(),
        );
    }

    info!(
        path = %path.display(),
        count = files.len(),
        mapping_count = mappings.len(),
        "Patching CIL source policy with .te files"
    );

    let mut policy = CilSourcePolicy::from_file(path)
        .map_err(|e| format!("failed to load CIL source {}: {}", path.display(), e))?;

    policy
        .load_mapping_files(mappings)
        .map_err(|e| format!("failed to load mapping CIL files: {}", e))?;

    for te_path in files {
        policy.load_rules_from_file(te_path, macros).map_err(|e| {
            format!(
                "failed to render CIL patch from {}: {}",
                te_path.display(),
                e
            )
        })?;
    }

    policy.write(out_path).map_err(|e| {
        format!(
            "failed to write patched CIL file {}: {}",
            out_path.display(),
            e
        )
    })?;

    info!(path = %out_path.display(), "Wrote patched CIL source policy");
    Ok(())
}

fn main() -> ExitCode {
    // Initialize tracing subscriber
    log::init_subscriber();

    let cli = Cli::parse();

    if !cli.split_cils.is_empty() && !cli.source.compile_split {
        error!("'--split-cil' can only be used together with '--compile-split'");
        return ExitCode::FAILURE;
    }

    // Handle extraction directly from CIL without compiling to policydb first.
    if let Some(Commands::Extract { labels }) = &cli.command {
        let results = match extract_from_cil_source(&cli.source, labels) {
            Ok(results) => results,
            Err(e) => {
                error!(error = %e, "Failed to extract labels from CIL source");
                return ExitCode::FAILURE;
            }
        };

        print_cil_results(&results);
        return ExitCode::SUCCESS;
    }

    if let Some(Commands::Patch {
        files,
        macros,
        mappings,
        output,
        #[cfg(target_os = "android")]
        live_patch,
    }) = &cli.command
    {
        if cli.source.cil.is_some() {
            if let Err(e) = patch_cil_source(
                &cli.source,
                files,
                macros,
                mappings,
                output.as_ref(),
                #[cfg(target_os = "android")]
                *live_patch,
            ) {
                error!(error = %e, "Failed to patch CIL source");
                return ExitCode::FAILURE;
            }

            return ExitCode::SUCCESS;
        }
    }

    // Determine the source and load the policy
    let mut sepolicy = match load_policy_from_source(&cli.source, &cli.split_cils) {
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
            mappings: _,
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
            println!(
                "Use 'extract <label> [label ...]' with '--cil <FILE>' to query CIL statements."
            );
        }
    }

    ExitCode::SUCCESS
}
