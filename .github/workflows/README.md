# 🔄 CI/CD Workflows

This directory contains the complete CI/CD pipeline for the ThreatFlux Package Security Library.

## 📋 Workflow Overview

| Workflow | Trigger | Purpose | Duration |
|----------|---------|---------|----------|
| [`ci.yml`](ci.yml) | Push/PR | Library testing pipeline | ~6-10 min |
| [`release.yml`](release.yml) | Tag push | Library release automation | ~8-12 min |
| [`docs.yml`](docs.yml) | Push to main | API documentation building | ~4-6 min |
| [`security.yml`](security.yml) | Push/PR/Schedule | Security scanning | ~10-15 min |
| [`dependency-update.yml`](dependency-update.yml) | Schedule/Manual | Dependency updates | ~5-10 min |

## 🚀 CI Pipeline (`ci.yml`)

### Quick Checks (< 3 min)
- ✅ Code formatting (`cargo fmt`)
- ✅ Linting (`cargo clippy`)
- ✅ Documentation generation

### Comprehensive Testing (< 8 min)
- 🔧 **Multi-platform**: Ubuntu, Windows, macOS
- 🦀 **Multi-Rust**: stable, beta, MSRV (1.95.0), nightly
- 📦 **Feature Testing**: Library features tested individually
- 🧪 **Integration tests**: Library integration and comprehensive tests
- 📊 **Performance**: Benchmarking on PRs

### Feature Testing
The library is tested with different feature combinations:
- `default` (includes concurrent)
- `concurrent` (concurrent analysis capabilities)
- `offline` (disable online vulnerability database updates)
- Combined features (`concurrent,offline`)

### Cross-Platform Verification
Library compatibility verified on:
- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`
- `x86_64-apple-darwin`

## 🎯 Release Pipeline (`release.yml`)

### Automated Release Process
1. **Validation**: Version format and pre-release checks
2. **Testing**: Full CI pipeline execution
3. **Packaging**: Library crate packaging and source archives
4. **Changelog**: Automatic generation from commits and PRs
5. **GitHub Release**: Automated creation with library packages
6. **Versioning**: Library version updates
7. **Registry**: Optional crates.io publishing

### Release Types
- **Patch**: Bug fixes (`v1.0.1`)
- **Minor**: New features (`v1.1.0`)
- **Major**: Breaking changes (`v2.0.0`)
- **Prerelease**: Alpha/beta versions (`v1.0.0-alpha.1`)

## 📚 Documentation Pipeline (`docs.yml`)

### Documentation Generation
- 🦀 **Rust Docs**: Complete API documentation with `rustdoc`
- 📖 **Library Examples**: Usage examples and code patterns
- 🔍 **Quality Checks**: Missing documentation detection
- 🌐 **Deployment**: GitHub Pages integration

### Documentation Coverage
- Library API documentation
- Private items documentation
- Code examples and doctests
- Usage patterns and examples
- Module-level documentation

## 🔒 Security Pipeline (`security.yml`)

### Comprehensive Security Scanning
- 🔍 **Cargo Audit**: Rust security advisories
- 📋 **Cargo Deny**: License and dependency validation
- 🛡️ **CodeQL**: Static code analysis
- 🔎 **Semgrep**: Security pattern detection
- 🔗 **Supply Chain**: Dependency security analysis
- 🔐 **Secrets**: Git history secret scanning
- 📦 **Container**: Docker image scanning (if applicable)

### Security Features
- Daily scheduled scans
- SARIF report generation
- Security badge generation
- Automatic issue creation for vulnerabilities

## 📦 Dependency Management (`dependency-update.yml`)

### Automated Updates
- 🔄 **Cargo Dependencies**: Rust crate updates
- 🔒 **Security Updates**: High-priority vulnerability fixes
- 🟢 **Node.js**: npm package updates (if applicable)
- 🧹 **Cleanup**: Old branch removal

### Update Strategies
- **Patch**: Safe bug fixes (default)
- **Minor**: New features (compatible)
- **Major**: Breaking changes (manual approval)
- **Security**: Immediate vulnerability fixes

## 🤖 Dependabot Configuration

Automated dependency updates via [`dependabot.yml`](../dependabot.yml):
- **Cargo**: Weekly Rust dependency updates
- **GitHub Actions**: Weekly workflow updates
- **npm**: Weekly Node.js updates (if applicable)
- **Docker**: Weekly base image updates (if applicable)

## 👥 Code Ownership ([`CODEOWNERS`](../CODEOWNERS))

Ensures proper review for sensitive files:
- 🔒 Security files require security team review
- 🚀 Workflows require DevOps team review
- 📚 Documentation requires docs team review
- ⚖️ Legal files require legal team review

## 📝 Issue & PR Templates

### Issue Templates
- 🐛 **Bug Report**: Structured bug reporting
- ✨ **Feature Request**: Feature proposal format
- 🔒 **Security Report**: Vulnerability reporting (public low-risk only)

### PR Templates
- 📋 **Default**: Comprehensive change documentation
- 🔒 **Security Fix**: Security-focused review process

## 🎯 Quality Gates

### Required Checks
- ✅ Code formatting (`cargo fmt --check`)
- ✅ Linting (`cargo clippy` with deny warnings)
- ✅ All tests pass
- ✅ Documentation builds
- ✅ Security audit passes
- ✅ Proper code review

### Performance Requirements
- ⚡ Fast feedback (< 10 minutes for basic checks)
- 🔄 Parallel execution where possible
- 💾 Intelligent caching
- 📊 Regression detection

## 📊 Monitoring & Reporting

### Workflow Status
- Real-time status in GitHub Actions
- Comprehensive summaries in workflow outputs
- Artifact retention for debugging
- Performance metrics tracking

### Security Monitoring
- Daily security scans
- Vulnerability trend tracking
- Dependency risk assessment
- Compliance reporting

## 🛠️ Development Workflow

### For Contributors
1. Fork and create feature branch
2. Make changes with tests
3. Run local checks: `cargo fmt`, `cargo clippy`, `cargo test`
4. Submit PR with appropriate template
5. Address review feedback
6. Merge after approval

### For Maintainers
1. Review PR against quality gates
2. Verify CI passes completely
3. Check security implications
4. Merge with appropriate labels
5. Monitor post-merge CI
6. Release when appropriate

## 🚨 Emergency Procedures

### Security Incidents
1. Report critical vulnerabilities privately to security@threatflux.com
2. Use security PR template for fixes
3. Follow coordinated disclosure timeline
4. Create immediate patch release
5. Notify users via security advisory

### CI/CD Failures
1. Check workflow status and logs
2. Identify root cause
3. Apply hotfix if critical
4. Update workflows if needed
5. Document lessons learned

## 📈 Future Enhancements

### Planned Improvements
- 🔬 Enhanced static analysis
- 📊 Performance regression testing
- 🌍 Internationalization testing
- 🔌 Plugin system CI
- 📱 Mobile platform support

### Metrics & Analytics
- Build time optimization
- Test coverage trending
- Security posture tracking
- Dependency health monitoring

---

For questions about the CI/CD pipeline, please open an issue or contact the DevOps team.