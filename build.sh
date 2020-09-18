# TODO I need to make this into a set of github actions or build configs for the app or something

# pwdb is easy running `cargo build` works, all the below instructions are for running in the pwa dir

# in PWA run to create all the associated JSON files
wasm-pack build --target web --out-name wasm --out-dir ./static

# Running `python3 -m http.server` in the root pwa is the easiest way (if already installed) to run it for debugging
# an alternative is `cargo install miniserver` folllowed by `miniserve ./static --index index.html`
# for either then browse to http://127.0.0.1:8000 !! Note browsing to http://0.0.0.0:8000 will not work for opening files

# For install to a github pages, I should build it the copy over all the files in the service-worker.js cache list