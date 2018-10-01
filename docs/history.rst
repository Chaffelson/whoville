History
-------

0.0.1-rc1
    24 Sept 2018

- Initial Release for beta testing

0.0.1-rc2
    25 Sept 2018

- Added default definitions:
- cda301-compact, HDP301 + HDF320 in single node
- hcp160, HCP160 in multi node setup
- hdp301-compact, hdp301 in single node quickstart config

- Added support for GET and CALL in definitions against orchestrator properties and functions
- Added support to pass a definition key like 'hcp160' to mayor.autorun() to bypass priority settings and just build that key
- Various bugfixes
- Added support for passing Cloudbreak deployer a version number in the Profile, e.g. 2.7.1


0.0.1-rc3
    26 Sept 2018

- refactored sequencing primitives to remove name clash and be more readable - please update definitions
- Moved sequencing primitives into actions.py
- Refactored borg singleton to support iteraction and basic parameter setting, more to come
- Documentation updates


0.0.1-rc4
    28 Sept 2018

- refactored naming to be clearer
- Added copy_def and merge_def primitives for future demo script usage
- Added cmdline menu for Quickstart and Docker consumption
- Tidied up exemplar definitions