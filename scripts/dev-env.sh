# Source this before building:  . scripts/dev-env.sh
#
# LATTICE builds with zig as the C compiler and linker (via cargo-zigbuild), so no
# system gcc or root access is needed, and the release binary links statically
# against musl. scripts/install-toolchain.sh sets all of this up in user space.
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
export CARGO_TERM_PROGRESS_WHEN=never
