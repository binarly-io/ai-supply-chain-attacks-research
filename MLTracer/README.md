# MLTracer: Syscall-Based Malicious Model Detection and Labeling, with Static-Scanner Evasion Taxonomy

Blog post: TBD

## Files

| File | Description |
| --- | --- |
| [hf_detection_status_20260225_pub.csv](hf_detection_status_20260225_pub.csv) | List of malicious model files detected by MLTracer, including detection results from existing model scanners. |
| [evasion.md](evasion.md) | Systematic analysis of how malicious model files evade existing model scanners. |

## Reporting

### Multiple False Negative Issues

- [ModelScan](https://github.com/protectai/modelscan/issues/338)
- [SaferPickle](https://github.com/google/saferpickle/issues/18)

### Bug Report

- [PyTorch](https://github.com/pytorch/pytorch/pull/169570) (out-of-bounds read)
