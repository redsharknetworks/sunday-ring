# Dummy generate_ioc.py - outputs static dummy data
with open('exports/csv/iocs.csv','w') as f:
    f.write('ip,country,asn,isp,score,sources\n')
    f.write('1.2.3.4,MY,12345,DummyISP,50,Talos\n')