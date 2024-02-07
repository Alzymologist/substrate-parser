# v0.5.0

New features:

- MetadataV15 support
- `AsMetadata` trait now requires milder implementation, so that it is usable on shortened metadata
- `AsCompleteMetadata` trait should be used instead now for full functionality (including events and database parsing)

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


