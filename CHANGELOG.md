# v0.6.1

- Add interpretation of `TxVersion` in struct fields, not only extensions
- Some functions made public
- Dependency bumps

# v0.6.0

API changes:

- Features simplified: it's either `std` (default), or `no-std`. Features were removed, thus version bump

Other changes

- Bring documentation up to date
- Remove `sp-core` and `sp-runtime` dependencies

# v0.5.0

New features:

- MetadataV15 support
- `AsMetadata` trait now requires milder implementation, so that it is usable on shortened metadata
- `AsCompleteMetadata` trait should be used instead now for full functionality (parsing of unchecked extrinsics)

API changes:

- What used to be `AsMetadata` might need to become `AsCompleteMetadata`, see above

# v0.4.0

This is a major rehaul of crate. Older versions are going into deprecation soon, as they are desperately obsolete at this point.

Features:

- `no-std` compatibility
- External memory support to dynamically access metadata and call without full copy into memory space
- Shortened metadata support
- More sane short specs structure
- Properly parse unchecked extrinsics

Bug fixes:

- Multiple minor fixes in rarely used extrinsic structure


