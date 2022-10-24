This dir contains the rust source code of openvas.

It is split into multiple libraries:
- ./nasl-syntax/ - is the syntax representation of nasl
- ./nasl-interpreter/ - is the nasl execution based on the nasl-syntax
- ./sink/ - is a database abstraction library
- ./sink-redis/ - is the sink implementation for redis
- ./nasl-cli - is a program to run the rust nasl implementation without openvas integration
