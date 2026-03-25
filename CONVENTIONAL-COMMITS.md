# Conventional Commits and Changelog Handling

All specifiers (Add, Change, Remove, Fix, Doc, Refactor, Test) need an ":" at the end (e.g. Fix:) to be recognized by pontos for changelog generation

The conventional commit can also just be the PR merge commit which can be edited via Github UI if the PR is just about one change. So both ways of developing (fine grained commits vs bigger commits) can be used.

Since the project has an autolabel for releasing, please consider the following status.

|Status | Explanation | Release |
|---|---|---|
| Add: | Added some feature | minor |
| Remove: | Removed functionality | major |
| Change: | Breaking change in public interface | major |
| Fix: | Fixed a bug | patch |

E.g. if you add a `change` commit, a `major` label will be automatic generated and once the PR is merged, a major release will be created. Only use `change` if it is a breaking change.
