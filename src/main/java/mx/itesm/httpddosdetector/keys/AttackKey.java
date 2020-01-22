package mx.itesm.httpddosdetector.keys;

public class AttackKey {
    public Integer srcip; 
    public Integer dstip; 
    public Integer dstport;
 
    public AttackKey(Integer srcip, Integer dstip, Integer dstport) {
       this.srcip = srcip;
       this.dstip = dstip;
       this.dstport = dstport;
    }
 
    @Override   
    public boolean equals(Object obj) {
        if (!(obj instanceof AttackKey))
            return false;
        AttackKey ref = (AttackKey) obj;
        return this.srcip.equals(ref.srcip) &&
            this.dstip.equals(ref.dstip) &&
            this.dstport.equals(ref.dstport);
    }
 
    @Override
    public int hashCode() {
        return srcip.hashCode() ^ dstip.hashCode() ^ dstport.hashCode();
    }
 
 }