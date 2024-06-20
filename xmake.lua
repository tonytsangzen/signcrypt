add_rules("mode.debug", "mode.release")
add_requires("sodium")

target("tbsbr")
    set_kind("static")
    add_files("signcrypt.c")

target("test")
    set_kind("binary")
    add_files("test.c")
	add_packages("sodium")
    add_deps("tbsbr")


