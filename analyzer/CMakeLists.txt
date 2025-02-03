spicy_add_analyzer(
    NAME C1222
    PACKAGE_NAME spicy-c1222
    SOURCES c1222.spicy c1222.evt zeek_c1222.spicy
    SCRIPTS __load__.zeek main.zeek c1222_types.zeek c1222_processing.zeek dpd.sig
)
