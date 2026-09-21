let meta = #{
    name: "merge-upstream",
    description: "Inspect GROK_COMPAT hook files against xAI grok-build and write a merge checklist",
    when_to_use: "Before merging xai-org/grok-build into this product fork",
    phases: [
        #{ title: "Scan", detail: "hook files vs upstream" },
        #{ title: "Advise", detail: "merge checklist" },
    ],
};

let scan_schema = #{
    "type": "object",
    "required": ["files"],
    "properties": #{
        "files": #{
            "type": "array",
            "maxItems": 16,
            "items": #{
                "type": "object",
                "required": ["path", "risk", "note"],
                "properties": #{
                    "path": #{ "type": "string" },
                    "risk": #{ "type": "string" },
                    "note": #{ "type": "string" },
                },
            },
        },
    },
};

let from_ref = "upstream/main";
if args != () && args.from != () {
    from_ref = args.from;
}

fn allowed_path(path) {
    if type_of(path) != "string" { return false; }
    path.starts_with("crates/codegen/xai-grok-sampler/")
        || path.starts_with("crates/codegen/xai-grok-shell/")
        || path.starts_with("crates/codegen/xai-grok-pager/")
}

phase("Scan");
let encoded_ref = json_encode(from_ref);
let jobs = [];

let p1 = "Compare HEAD to git ref ";
p1 += encoded_ref;
p1 += " for GROK_COMPAT hook files in the sampler. Use grep for GROK_COMPAT_HOOK and git diff HEAD...";
p1 += from_ref;
p1 += " -- crates/codegen/xai-grok-sampler/src/client.rs crates/codegen/xai-grok-sampler/src/compat.rs crates/codegen/xai-grok-sampler/src/stream/responses.rs crates/codegen/xai-grok-sampler/src/actor/request_task.rs. Read the current files. Report at most 16 {path, risk, note} where risk is low/medium/high. Empty files is valid only after you ran git diff. Stay under crates/codegen/xai-grok-sampler/.";
jobs.push(#{
    prompt: p1,
    label: "scan-sampler",
    capability_mode: "read-only",
    output_schema: scan_schema,
});

let p2 = "Compare HEAD to git ref ";
p2 += encoded_ref;
p2 += " for GROK_COMPAT hook files in the shell. Use grep for GROK_COMPAT_HOOK and git diff HEAD...";
p2 += from_ref;
p2 += " -- crates/codegen/xai-grok-shell/src/agent/config.rs crates/codegen/xai-grok-shell/src/agent/remote_config/manager/mod.rs crates/codegen/xai-grok-shell/src/agent/mvp_agent/acp_agent.rs crates/codegen/xai-grok-shell/src/session/acp_session_impl/sampler_turn.rs crates/codegen/xai-grok-shell/src/extensions/notification.rs. Read crates/codegen/xai-grok-shell/src/compat/UPSTREAM.md. Catalog overlay is remote_config/manager, not agent/models.rs. Report at most 16 {path, risk, note}. Stay under crates/codegen/xai-grok-shell/.";
jobs.push(#{
    prompt: p2,
    label: "scan-shell",
    capability_mode: "read-only",
    output_schema: scan_schema,
});

let p3 = "Compare HEAD to git ref ";
p3 += encoded_ref;
p3 += " for vendor Action/Effect/TaskResult and slash-command registration in the pager. git diff HEAD...";
p3 += from_ref;
p3 += " -- crates/codegen/xai-grok-pager/src/app/actions.rs crates/codegen/xai-grok-pager/src/app/dispatch crates/codegen/xai-grok-pager/src/app/dispatch/modes.rs crates/codegen/xai-grok-pager/src/slash/commands/mod.rs. Report at most 16 {path, risk, note} about merge conflicts (enum variants, match arms, set_fast_mode). Stay under crates/codegen/xai-grok-pager/. Empty files is valid only after you ran git diff.";
jobs.push(#{
    prompt: p3,
    label: "scan-pager",
    capability_mode: "read-only",
    output_schema: scan_schema,
});

let results = parallel(jobs);
let files = [];
let dropped = 0;
for r in results {
    if r == () || !r.success || r.output.files == () { continue; }
    for f in r.output.files {
        if allowed_path(f.path) {
            files.push(f);
        } else {
            dropped += 1;
        }
    }
}
if dropped > 0 {
    log("dropped " + dropped.to_string() + " out-of-scope paths");
}

phase("Advise");
let encoded_files = json_encode(files);
let advise_prompt = "Write a merge checklist for this product fork of grok-build. Read crates/codegen/xai-grok-shell/src/compat/UPSTREAM.md first. The scan of hook files vs ";
advise_prompt += encoded_ref;
advise_prompt += " is: ";
advise_prompt += encoded_files;
advise_prompt += " Use read_file on that playbook. The merge is manual (git merge --no-ff); do not merge. Output markdown: 1) whether to merge now, 2) hook files likely to conflict, 3) smoke tests from the playbook. Keep it under 80 lines.";
let advice = agent(advise_prompt, #{
    label: "advise",
    capability_mode: "read-only",
});

let report = "# merge-upstream checklist\n\nref: " + from_ref + "\n\n";
if advice != () && advice.success && type_of(advice.output) == "string" && advice.output != "" {
    report += advice.output;
} else {
    report += "Advisor did not return a checklist. Re-run after `git fetch upstream`.\n";
    report += "Playbook: crates/codegen/xai-grok-shell/src/compat/UPSTREAM.md\n";
    report += "Dry-run: ./scripts/merge-upstream.sh\n";
}

let path = write_scratch_file("merge-upstream.md", report);
complete(#{
    path: path,
    from: from_ref,
    hook_findings: files.len(),
});
