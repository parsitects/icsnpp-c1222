from scapy.all import *
from c1222_classes import *

service_error_resp=Service(
    serviceTag=RequestResponseCodes.ISSS.value
)