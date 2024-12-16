# @TEST-DOC: Check that the C12.22 analyzer is available.
#
@TEST-EXEC: [ $(zeek -NN | grep -i -c 'ANALYZER__\?C1222_..P') -eq 2 ]
