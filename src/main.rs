use clap::{Parser, Subcommand, ValueEnum};
use sepolicy::SePolicy;
use std::path::PathBuf;
use std::process::ExitCode;

/// SELinux Policy Injection Tool
#[derive(Parser)]
#[command(name = "sepolicy-inject-rs")]
#[command(author, version, about, long_about = None)]
#[command(
    after_help = "If neither --load, --load-split, nor --compile-split is specified, it will load from current live policies (/sys/fs/selinux/policy)"
)]
struct Cli {
    /// Load monolithic sepolicy from a file
    #[arg(long, group = "source", conflicts_with_all = ["load_split", "compile_split"])]
    load: Option<PathBuf>,

    /// Load from precompiled sepolicy or compile split cil policies
    #[arg(long, group = "source", conflicts_with_all = ["load", "compile_split"])]
    load_split: bool,

    /// Compile split cil policies
    #[arg(long, group = "source", conflicts_with_all = ["load", "load_split"])]
    compile_split: bool,

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
    let cli = Cli::parse();

    // Determine the source and load the policy
    let sepolicy = if let Some(ref file) = cli.load {
        SePolicy::from_file(file)
    } else if cli.load_split {
        SePolicy::from_split()
    } else if cli.compile_split {
        SePolicy::compile_split()
    } else {
        SePolicy::from_file("/sys/fs/selinux/policy")
    };

    let sepolicy = match sepolicy {
        Some(s) => s,
        None => {
            eprintln!("Error: Cannot load policy");
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
                println!("{}", rule);
            }
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
        }
    }

    ExitCode::SUCCESS
}
