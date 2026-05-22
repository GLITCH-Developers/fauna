use anyhow::Result;
use clap::{Parser, Subcommand};
use fauna_core::{DeviceIdentity, Invite};

mod p2p;

#[derive(Debug, Parser)]
#[command(name = "fauna")]
#[command(about = "Developer CLI for the Fauna P2P messaging foundation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a new local device identity.
    Identity,

    /// Generate a shareable invite for a newly generated identity.
    Invite {
        #[arg(long)]
        name: String,

        #[arg(long = "addr")]
        addresses: Vec<String>,
    },

    /// Decode a fauna:// invite link.
    DecodeInvite { invite: String },

    /// Host a direct encrypted chat from this computer.
    Host {
        #[arg(long)]
        name: String,

        #[arg(long, default_value = "0.0.0.0:45123")]
        bind: String,

        #[arg(long)]
        public_addr: Option<String>,
    },

    /// Join a direct encrypted chat using a fauna:// invite.
    Join {
        #[arg(long)]
        name: String,

        invite: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Identity => {
            let identity = DeviceIdentity::generate();
            println!("{}", serde_json::to_string_pretty(&identity.export())?);
        }
        Command::Invite { name, addresses } => {
            let identity = DeviceIdentity::generate();
            let invite = addresses
                .into_iter()
                .fold(Invite::new(&identity, name), |invite, address| {
                    invite.with_address(address)
                });

            println!("{}", invite.encode()?);
        }
        Command::DecodeInvite { invite } => {
            let invite = Invite::decode(&invite)?;
            println!("{}", serde_json::to_string_pretty(&invite)?);
        }
        Command::Host {
            name,
            bind,
            public_addr,
        } => {
            p2p::host(name, bind, public_addr)?;
        }
        Command::Join { name, invite } => {
            p2p::join(name, invite)?;
        }
    }

    Ok(())
}
