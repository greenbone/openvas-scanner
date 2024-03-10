# openvas-scanner contribution agreement

We want to relicense our code to `GPL-3.0-or-later` or `AGPL-3.0-or-later` in the future. Although most of the new code is licensed under `GPL-2.0-or-later` we want to make sure that no problems accure when relicensing. Your contributions are licensed under `MIT-0` and instantly relicensed to our currently used license. This means either `GPL-2.0-or-later` or `GPL-2.0`. Rust code is currently licensed with `GPL-2.0-or-later` per default. C code depends on the location and changes.

Please read and commit the /template/template.txt as [Name].md in this folder with your first PR. Having a valid `git.user.name` and `git.user.email` is sufficient.

Example usage:

```
# check with e.g. `git config --list` if you have a valid `user.name` and `user.email` set.
$ git config --list
    user.email=Jane.Doe@example.com
    user.name=jane Doe
    ....

# Commit the template
$ cd {path_to_openvas-scanner}/openvas-scanner/RELICENSE
$ cp ./template/template.txt JDoe.md
$ git add JDoe.md
$ git commit
```

Happy hacking!