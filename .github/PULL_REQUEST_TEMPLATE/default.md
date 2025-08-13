# Pull Request

## 📋 Summary

<!-- Provide a brief description of the changes in this PR -->

## 🔗 Related Issues

<!-- Link to related issues using "Fixes #123" or "Addresses #123" -->
- Fixes #
- Related to #

## 📝 Type of Change

<!-- Mark the type of change with an [x] -->

- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ New feature (non-breaking change that adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 Documentation update
- [ ] 🔧 Refactoring (no functional changes)
- [ ] ⚡ Performance improvement
- [ ] 🔒 Security enhancement
- [ ] 🧪 Test improvements
- [ ] 🏗️ Build system changes
- [ ] 📦 Dependency updates

## 🔍 Changes Made

<!-- Describe the changes in detail -->

### Core Changes
- 
- 
- 

### Files Modified
<!-- List the main files that were changed and why -->
- `src/file.rs` - 
- `Cargo.toml` - 
- 

## 🧪 Testing

<!-- Describe how you tested your changes -->

### Test Coverage
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed
- [ ] Existing tests still pass

### Test Commands
```bash
# Commands used to test the changes
cargo test
cargo test --workspace --all-features
./target/release/file-scanner test-file.bin
```

### Test Results
<!-- Paste relevant test output or describe results -->
```
Test results here...
```

## 📊 Performance Impact

<!-- If applicable, describe any performance implications -->

- [ ] No performance impact
- [ ] Performance improvement (describe below)
- [ ] Performance regression (justify why acceptable)
- [ ] Performance impact unknown/requires benchmarking

### Benchmarks
<!-- If you ran benchmarks, include results -->

## 🔒 Security Considerations

<!-- Address any security implications -->

- [ ] No security impact
- [ ] Security improvement (describe below)
- [ ] Potential security implications (described in detail below)
- [ ] Security review required

### Security Notes
<!-- Describe any security considerations, new attack surfaces, or mitigations -->

## 📖 Documentation

<!-- Mark what documentation was updated -->

- [ ] Code comments updated
- [ ] README.md updated
- [ ] API documentation updated (rustdoc)
- [ ] CLI help text updated
- [ ] CLAUDE.md updated
- [ ] No documentation changes needed

## ✅ Pre-Submission Checklist

<!-- Verify all items before submitting -->

### Code Quality
- [ ] Code follows the project's style guidelines
- [ ] `cargo fmt` has been run
- [ ] `cargo clippy` passes without warnings
- [ ] No unnecessary debug code or comments left in

### Testing
- [ ] All tests pass locally
- [ ] New tests have been added for new functionality
- [ ] Edge cases are covered by tests
- [ ] Error handling is tested

### Documentation
- [ ] Public APIs are documented
- [ ] Complex logic is commented
- [ ] User-facing changes are documented
- [ ] Breaking changes are clearly marked

### Compatibility
- [ ] Changes are backward compatible OR breaking changes are documented
- [ ] MSRV (Minimum Supported Rust Version) is maintained
- [ ] Cross-platform compatibility considered
- [ ] MCP integration still works (if applicable)

## 🚀 Deployment Notes

<!-- Any special considerations for deployment -->

- [ ] No special deployment requirements
- [ ] Database migration required
- [ ] Configuration changes required
- [ ] Dependencies need updating
- [ ] Breaking changes require version bump

### Migration Guide
<!-- If breaking changes, provide migration guidance -->

## 🔄 Post-Merge Tasks

<!-- Tasks to complete after merging -->

- [ ] Update version numbers
- [ ] Update changelog
- [ ] Create release notes
- [ ] Update documentation website
- [ ] Notify stakeholders

## 💬 Additional Notes

<!-- Any other information reviewers should know -->

### Review Focus Areas
<!-- What should reviewers pay special attention to? -->
- 
- 
- 

### Questions for Reviewers
<!-- Specific questions or areas where you'd like feedback -->
- 
- 
- 

---

<!-- 
Reviewer Guidelines:
- Check code quality and style
- Verify test coverage
- Review security implications
- Test the changes locally
- Ensure documentation is adequate
- Validate performance impact
-->

**For Reviewers:**
- [ ] Code review completed
- [ ] Tests verified
- [ ] Documentation reviewed
- [ ] Security implications considered
- [ ] Performance impact assessed