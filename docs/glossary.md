# Glossary

Short definitions for acronyms used across kompli's docs.

| Term | Meaning |
|---|---|
| MC | Machine Configuration, the Azure service that drives compliance audits and remediations on a VM. |
| NRP | Native Resource Provider, the shared library MC loads to run kompli's audit/remediate logic. |
| GC | Guest Configuration, the Azure worker process that loads the NRP adapter and drives it through MOF. |
| MOF | Managed Object Format, the text file format GC uses to describe what to audit or remediate. |
| MIM | Management Information Model, the schema that declares a component's properties for a management agent. |
| ASB | Azure Security Baseline, the sibling NRP module that ships alongside kompli's Compliance module. |
| MMI | Management Module Interface, the retired OSConfig-era protocol for talking to a per-rule module. |
| MPI | Management Platform Interface, the retired OSConfig-era transport between a module and the platform daemon. |
