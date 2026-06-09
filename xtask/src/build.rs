use std::process::Command;

use anyhow::Context as _;
use clap::Parser;

use crate::{
    build_ebpf::{build_ebpf, Architecture, Backend, Options as BuildOptions},
    build_frontend::{build_frontend, Options as FrontendOptions},
};

#[derive(Debug, Parser)]
pub struct Options {
    /// Select which eBPF implementation to build
    #[clap(default_value = "libbpf", long)]
    pub backend: Backend,
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    #[clap(long)]
    pub disable_resource_saving: bool,
    /// Skip building the web frontend
    #[clap(long)]
    pub skip_frontend: bool,
    /// Skip installing frontend dependencies before building
    #[clap(long)]
    pub skip_frontend_deps: bool,
    /// Extra cargo features to activate for the userspace build, comma or space
    /// separated. May be repeated. The backend feature is selected by
    /// `--backend` and does not need to be listed here.
    #[clap(long, value_delimiter = ',')]
    pub features: Vec<String>,
    /// Build the userspace binary without the crate's default cargo features
    /// (e.g. to link against a system libbpf instead of the vendored one)
    #[clap(long)]
    pub no_default_features: bool,
}

/// Resolve the `--features` / `--no-default-features` arguments for the
/// userspace `cargo build`, reconciling the user supplied features with the
/// backend selected via `--backend`.
///
/// The userspace crate refuses to compile when both backend features are
/// enabled or when neither is, so we sort that out here rather than letting it
/// fail deep inside the build:
///   * the backend feature normally comes from the default features, so it is
///     added back whenever default features are disabled, and
///   * requesting the *other* backend's feature is rejected up front.
fn cargo_feature_args(
    backend: Backend,
    user_features: &[String],
    no_default_features: bool,
) -> Result<Vec<String>, anyhow::Error> {
    let (backend_feature, other_backend, other_feature) = match backend {
        Backend::Libbpf => ("ebpf-libbpf", Backend::Aya, "ebpf-aya"),
        Backend::Aya => ("ebpf-aya", Backend::Libbpf, "ebpf-libbpf"),
    };

    if user_features.iter().any(|f| f == other_feature) {
        anyhow::bail!(
            "feature `{other_feature}` conflicts with `--backend {backend}`; \
             the backend is selected by `--backend`, so drop the feature \
             or pass `--backend {other_backend}` instead",
        );
    }

    // The aya backend pulls in default features that are specific to (and only
    // make sense for) the libbpf backend, so it is always built without them.
    let no_default_features = no_default_features || backend == Backend::Aya;

    let mut features = user_features.to_vec();
    // Keep the selected backend enabled even when default features are off.
    if no_default_features && !features.iter().any(|f| f == backend_feature) {
        features.push(backend_feature.to_owned());
    }

    let mut args = Vec::new();
    if no_default_features {
        args.push("--no-default-features".to_owned());
    }
    if !features.is_empty() {
        args.push("--features".to_owned());
        args.push(features.join(","));
    }
    Ok(args)
}

/// Build the project
fn build_project(opts: &Options, feature_args: &[String]) -> Result<(), anyhow::Error> {
    let mut args = vec!["build".to_owned()];
    if opts.release {
        args.push("--release".to_owned())
    }
    args.extend_from_slice(feature_args);
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

/// Build our ebpf program and the project
pub fn build(opts: Options) -> Result<(), anyhow::Error> {
    // Validate and resolve the userspace feature flags up front so a bad
    // `--features`/`--backend` combination fails before the slow eBPF and
    // frontend builds run.
    let feature_args = cargo_feature_args(opts.backend, &opts.features, opts.no_default_features)?;

    // build our ebpf program followed by our application
    build_ebpf(BuildOptions {
        backend: opts.backend,
        target: opts.bpf_target,
        release: opts.release,
        disable_resource_saving: opts.disable_resource_saving,
    })
    .context("Error while building eBPF program")?;
    if !opts.skip_frontend {
        build_frontend(FrontendOptions {
            skip_frontend_deps: opts.skip_frontend_deps,
        })
        .context("Error while building frontend")?;
    }
    build_project(&opts, &feature_args).context("Error while building userspace application")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::cargo_feature_args;
    use crate::build_ebpf::Backend;

    fn feats(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn libbpf_default_adds_no_feature_flags() {
        // Default build is left untouched: the backend comes from the crate's
        // default features.
        assert!(cargo_feature_args(Backend::Libbpf, &[], false)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn aya_forces_no_default_features_and_its_backend_feature() {
        assert_eq!(
            cargo_feature_args(Backend::Aya, &[], false).unwrap(),
            feats(&["--no-default-features", "--features", "ebpf-aya"]),
        );
    }

    #[test]
    fn disabling_defaults_readds_the_libbpf_backend() {
        // `--no-default-features` would otherwise drop the only backend feature.
        assert_eq!(
            cargo_feature_args(Backend::Libbpf, &[], true).unwrap(),
            feats(&["--no-default-features", "--features", "ebpf-libbpf"]),
        );
    }

    #[test]
    fn extra_features_keep_defaults_when_not_disabled() {
        assert_eq!(
            cargo_feature_args(Backend::Libbpf, &feats(&["static"]), false).unwrap(),
            feats(&["--features", "static"]),
        );
    }

    #[test]
    fn extra_features_merge_with_readded_backend() {
        assert_eq!(
            cargo_feature_args(Backend::Libbpf, &feats(&["static"]), true).unwrap(),
            feats(&["--no-default-features", "--features", "static,ebpf-libbpf"]),
        );
    }

    #[test]
    fn explicit_backend_feature_is_not_duplicated() {
        assert_eq!(
            cargo_feature_args(Backend::Libbpf, &feats(&["ebpf-libbpf"]), true).unwrap(),
            feats(&["--no-default-features", "--features", "ebpf-libbpf"]),
        );
    }

    #[test]
    fn extra_features_merge_with_aya_backend() {
        assert_eq!(
            cargo_feature_args(Backend::Aya, &feats(&["foo"]), false).unwrap(),
            feats(&["--no-default-features", "--features", "foo,ebpf-aya"]),
        );
    }

    #[test]
    fn requesting_the_other_backend_feature_is_rejected() {
        let err = cargo_feature_args(Backend::Aya, &feats(&["ebpf-libbpf"]), false).unwrap_err();
        assert!(err.to_string().contains("conflicts with `--backend aya`"));

        let err = cargo_feature_args(Backend::Libbpf, &feats(&["ebpf-aya"]), true).unwrap_err();
        assert!(err.to_string().contains("conflicts with `--backend libbpf`"));
    }
}
