# Prior work and reuse

Everything in this repository was written during the Meta Global AI Developer Hackathon (Oct 26 - Nov 4, 2026). No code from earlier projects is included.

Third-party work we build on (all used as published, with attribution):

- [GuardDog](https://github.com/DataDog/guarddog) (Apache-2.0): rule-based npm scanner, planned as an evaluation baseline.
- [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (Apache-2.0): labeled malicious npm samples for training and evaluation. Samples are only ever unpacked inside isolated cloud containers.
- [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) and [OSV](https://osv.dev) (Apache-2.0): confirmation of detections and report format.
- [npm-high-impact](https://github.com/wooorm/npm-high-impact) (MIT): list of popular packages for typosquatting checks and benign data.
- [llama.cpp](https://github.com/ggml-org/llama.cpp) (MIT): local inference for Muse Glimmer.
- [Llama Guard 3 1B](https://huggingface.co/meta-llama/Llama-Guard-3-1B) (Llama 3.2 Community License): base model of the fine-tuned safety net (LoRA trained on ground truth only).
- Meta Muse models (Muse Spark, Muse Spark Open, Muse Glimmer) through the Meta Model API, Fireworks, Baseten and the official GGUF; Muse Code as the AI agent in the demo.
