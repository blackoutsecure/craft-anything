extern crate self as craft_anything_pr2_proof;

include!(concat!(env!("POC_PROOF_SOURCE"), "/src/lib.rs"));

mod guardrails {
    include!(concat!(env!("POC_PROOF_SOURCE"), "/tests/guardrails.rs"));
}

mod live_gui {
    include!(concat!(env!("POC_PROOF_SOURCE"), "/tests/live_gui.rs"));
}

mod persistence {
    include!(concat!(env!("POC_PROOF_SOURCE"), "/tests/persistence.rs"));
}
