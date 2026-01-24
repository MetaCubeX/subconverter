#!/bin/bash
set -e

# --- Configuration ---
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( dirname "$SCRIPT_DIR" )"
DEPS_SRC_DIR="$SCRIPT_DIR"
INSTALL_DIR="$ROOT_DIR/deps_install"
CPU_CORES=$(sysctl -n hw.ncpu || echo 4)
BREW_PREFIX=$(brew --prefix)

cd "$ROOT_DIR"

echo "Using Brew Prefix: $BREW_PREFIX"
echo "Using CPU Cores: $CPU_CORES"
echo "Install Directory: $INSTALL_DIR"

# 1. Base Dependencies
echo "Checking base dependencies..."
brew install rapidjson zlib pcre2 pkgconfig curl openssl@3

# 2. Helper Functions
function setup_repo() {
    local url=$1
    local dir=$2
    local ref=$3
    echo "--- Setting up $dir ($ref) ---"
    cd "$DEPS_SRC_DIR"
    if [ ! -d "$dir" ]; then
        git clone "$url" "$dir"
    fi
    cd "$dir"
    git fetch origin --tags
    git reset --hard "$ref"
}

# 3. Build Dependencies
mkdir -p "$INSTALL_DIR"

setup_repo "https://github.com/jbeder/yaml-cpp" "yaml-cpp" "master"
cmake -B build -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release \
      -DYAML_CPP_BUILD_TESTS=OFF -DYAML_CPP_BUILD_TOOLS=OFF \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"
cmake --build build -j "$CPU_CORES"
cmake --install build

setup_repo "https://github.com/ftk/quickjspp" "quickjspp" "master"
cmake -B build -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build --target quickjs -j "$CPU_CORES"
mkdir -p "$INSTALL_DIR/lib/quickjs" "$INSTALL_DIR/include/quickjs"
cp build/quickjs/libquickjs.a "$INSTALL_DIR/lib/quickjs/"
cp quickjs/quickjs.h quickjs/quickjs-libc.h "$INSTALL_DIR/include/quickjs/"
cp quickjspp.hpp "$INSTALL_DIR/include/"

setup_repo "https://github.com/PerMalmberg/libcron" "libcron" "master"
git submodule update --init
cmake -B build -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build --target libcron -j "$CPU_CORES"
mkdir -p "$INSTALL_DIR/include/libcron" "$INSTALL_DIR/include/date"
cp libcron/out/Release/liblibcron.a "$INSTALL_DIR/lib/"
cp -R libcron/include/libcron/* "$INSTALL_DIR/include/libcron/"
cp -R libcron/externals/date/include/date/* "$INSTALL_DIR/include/date/"

setup_repo "https://github.com/ToruNiina/toml11" "toml11" "main"
cmake -B build -G "Unix Makefiles" -DCMAKE_CXX_STANDARD=11 -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"
cmake --build build -j "$CPU_CORES"
cmake --install build

# 4. Main Program Build
cd "$ROOT_DIR"
echo "--- Building subconverter ---"
rm -rf build_root
cmake -B build_root -G "Unix Makefiles" \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_PREFIX_PATH="$INSTALL_DIR" \
      -DZLIB_ROOT="$BREW_PREFIX/opt/zlib" \
      -DPCRE2_ROOT="$BREW_PREFIX/opt/pcre2"
cmake --build build_root -j "$CPU_CORES"

# 5. Final Linking
echo "--- Final Linking ---"
rm -rf subconverter
LDFLAGS="-Xlinker -unexported_symbol -Xlinker \"*\" -framework CoreFoundation -framework Security"
LIBS="$(find "$INSTALL_DIR" -name "*.a") $BREW_PREFIX/opt/zlib/lib/libz.a $BREW_PREFIX/opt/pcre2/lib/libpcre2-8.a -lcurl"
OBJECTS="$(find build_root/CMakeFiles/subconverter.dir/src/ -name "*.o")"

c++ $LDFLAGS -o base/subconverter $OBJECTS $LIBS -O3

# 6. Update Rules
echo "--- Updating Rules ---"
python3 -m venv venv
source venv/bin/activate
pip install gitpython
python $SCRIPT_DIR/update_rules.py -c $SCRIPT_DIR/rules_config.conf
deactivate

# 7. Cleanup and Packaging
echo "--- Finishing ---"
cd base
chmod +rx subconverter
chmod +r ./*
cd ..

if [ -d "subconverter" ]; then rm -rf subconverter; fi
cp -R base subconverter
echo "Build complete! Output is in subconverter/"
