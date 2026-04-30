from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps
from conan.tools.files import copy


class SpeerConan(ConanFile):
    name = "speer"
    version = "0.1.0"
    license = "MIT"
    author = "speer contributors"
    url = "https://github.com/speer/speer"
    description = "A tiny libp2p implementation in C"
    topics = ("p2p", "networking", "libp2p", "crypto", "dht")
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "web_pki": [True, False],
        "relay": [True, False],
        "dht": [True, False],
        "mdns": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "web_pki": False,
        "relay": True,
        "dht": True,
        "mdns": True,
    }

    exports_sources = (
        "CMakeLists.txt",
        "speer.pc.in",
        "cmake/*",
        "include/*",
        "src/*",
        "tests/*",
        "examples/*",
        "tools/*",
        "LICENSE",
        "README.md",
    )

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.variables["SPEER_ENABLE_WEBPKI"] = self.options.web_pki
        tc.variables["SPEER_ENABLE_RELAY"] = self.options.relay
        tc.variables["SPEER_ENABLE_DHT"] = self.options.dht
        tc.variables["SPEER_ENABLE_MDNS"] = self.options.mdns
        tc.variables["SPEER_BUILD_TESTS"] = False
        tc.variables["SPEER_BUILD_EXAMPLES"] = False
        tc.variables["SPEER_BUILD_TOOLS"] = False
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        copy(self, "LICENSE", src=self.source_folder, dst=self.package_folder)
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["speer"]
        self.cpp_info.set_property("cmake_file_name", "speer")
        self.cpp_info.set_property("cmake_target_name", "speer::speer")
        self.cpp_info.set_property("pkg_config_name", "speer")

        if self.settings.os == "Windows":
            self.cpp_info.system_libs = ["ws2_32", "iphlpapi", "advapi32"]
        elif self.settings.os == "Linux":
            self.cpp_info.system_libs = ["m"]
