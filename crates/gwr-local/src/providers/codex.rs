//! The codex exec labor-provider adapter — the one real provider, behind the
//! existing neutral contract, with zero core changes.
//!
//! The adapter receives only the bounded assignment: a disposable populated
//! workspace, a goal, a basis, a deadline. It never receives governed target
//! credentials, standing tokens, reservation handles, dispatch permits, or
//! recovery authority — the contract has no channel for them. Everything codex
//! prints is provenance: stored as-said, never believed. The patch is collected
//! by the runtime from the workspace's own git diff; codex's opinion of what it
//! did does not enter the candidate.

use gwr_runtime::ports::labor_provider::{
    BoundedAssignment, LaborProvider, PreparationOutcome, PreparationReport, ProvenanceEntry,
    ProviderError, ProviderEvent, SequencedEvent,
};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Populate a disposable workspace with a detached checkout of the exact basis.
/// The origin remote is removed: the workspace has no path back to the governed
/// repository.
pub fn populate_workspace(repo: &str, basis: &str, dest: &Path) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(dest);
    let run = |args: &[&str]| -> Result<(), String> {
        let out = Command::new("git")
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!(
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(())
    };
    let dest_s = dest.to_string_lossy().to_string();
    run(&["clone", "-q", "--no-checkout", repo, &dest_s])?;
    run(&["-C", &dest_s, "checkout", "-q", "--detach", basis])?;
    run(&["-C", &dest_s, "remote", "remove", "origin"])?;
    Ok(())
}

pub struct CodexExecProvider {
    /// The codex binary. Contract tests substitute a fake executable speaking
    /// the same CLI surface.
    pub codex_bin: PathBuf,
    pub timeout: Duration,
}

impl CodexExecProvider {
    pub fn new() -> Self {
        Self {
            codex_bin: PathBuf::from("codex"),
            timeout: Duration::from_secs(600),
        }
    }
}

impl Default for CodexExecProvider {
    fn default() -> Self {
        Self::new()
    }
}

fn prompt_for(assignment: &BoundedAssignment) -> String {
    format!(
        "You are a bounded labor provider working in a disposable checkout at commit {}.\n\
         Goal: {}\n\
         Rules: work only inside the current directory; modify only the files the goal \
         requires; do not run `git commit`, `git push`, `git fetch`, or contact any \
         remote; leave your changes uncommitted in the working tree; do not create \
         new remotes. When you are done, stop.",
        assignment.basis.as_str(),
        assignment.goal
    )
}

fn workspace_diff(workspace: &Path) -> Result<Vec<u8>, String> {
    // Include new files via intent-to-add, then take the exact diff.
    let add = Command::new("git")
        .args([
            "-C",
            workspace.to_string_lossy().as_ref(),
            "add",
            "-A",
            "-N",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !add.status.success() {
        return Err("git add -N failed".into());
    }
    let diff = Command::new("git")
        .args(["-C", workspace.to_string_lossy().as_ref(), "diff"])
        .output()
        .map_err(|e| e.to_string())?;
    if !diff.status.success() {
        return Err("git diff failed".into());
    }
    Ok(diff.stdout)
}

fn kill_process_group(child: &mut Child) {
    let group = format!("-{}", child.id());
    let _ = Command::new("/bin/kill")
        .args(["-KILL", "--", &group])
        .status();
    let _ = child.kill();
    let _ = child.wait();
}

impl LaborProvider for CodexExecProvider {
    fn prepare(
        &mut self,
        assignment: &BoundedAssignment,
    ) -> Result<PreparationReport, ProviderError> {
        let workspace = assignment.workspace.clone();
        let prompt = prompt_for(assignment);
        let mut child = Command::new(&self.codex_bin)
            .arg("exec")
            .args(["-c", "approval_policy=\"never\""])
            .args(["--sandbox", "workspace-write"])
            .arg("--skip-git-repo-check")
            .args(["--cd", workspace.to_string_lossy().as_ref()])
            .arg(&prompt)
            .current_dir(&workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|e| ProviderError::Died(format!("spawn codex: {e}")))?;

        // Bounded: poll for completion; past the deadline the provider is dead.
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if started.elapsed() > self.timeout {
                        kill_process_group(&mut child);
                        return Err(ProviderError::Died(format!(
                            "codex exceeded bound of {:?}",
                            self.timeout
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(ProviderError::Died(format!("wait: {e}"))),
            }
        };
        let output = child
            .wait_with_output()
            .map_err(|e| ProviderError::Died(format!("collect output: {e}")))?;

        let mut provenance = vec![
            ProvenanceEntry {
                label: "codex_exit_code".into(),
                content: status.code().map_or("signal".into(), |c| c.to_string()),
            },
            ProvenanceEntry {
                label: "codex_stdout".into(),
                content: String::from_utf8_lossy(&output.stdout).into_owned(),
            },
            ProvenanceEntry {
                label: "codex_stderr".into(),
                content: String::from_utf8_lossy(&output.stderr).into_owned(),
            },
        ];
        let events = vec![
            SequencedEvent {
                seq: 0,
                event: ProviderEvent::Started,
            },
            SequencedEvent {
                seq: 1,
                event: ProviderEvent::CandidateReady,
            },
        ];

        if !status.success() {
            return Ok(PreparationReport {
                events,
                outcome: PreparationOutcome::Failed {
                    reason: format!("codex exited {:?}", status.code()),
                },
                provenance,
            });
        }

        // The runtime collects the patch; codex's testimony about its own work
        // stays in provenance.
        let patch =
            workspace_diff(&workspace).map_err(|e| ProviderError::Died(format!("diff: {e}")))?;
        if patch.is_empty() {
            provenance.push(ProvenanceEntry {
                label: "adapter_note".into(),
                content: "codex exited zero but produced no workspace changes".into(),
            });
            return Ok(PreparationReport {
                events,
                outcome: PreparationOutcome::Failed {
                    reason: "no changes produced".into(),
                },
                provenance,
            });
        }
        Ok(PreparationReport {
            events,
            outcome: PreparationOutcome::Candidate { patch },
            provenance,
        })
    }
}
