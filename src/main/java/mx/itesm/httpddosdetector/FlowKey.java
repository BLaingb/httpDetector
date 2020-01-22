package mx.itesm.httpddosdetector;

public class FlowKey {
    public Integer srcip; 
    public Integer srcport; 
    public Integer dstip; 
    public Integer dstport;
    public Byte proto;
 
    public FlowKey(Integer srcip, Integer srcport, Integer dstip, Integer dstport, Byte proto) {
       this.srcip = srcip;
       this.srcport = srcport;
       this.dstip = dstip;
       this.dstport = dstport;
       this.proto = proto;
    }
 
    @Override   
    public boolean equals(Object obj) {
        if (!(obj instanceof FlowKey))
            return false;
        FlowKey ref = (FlowKey) obj;
        return this.srcip.equals(ref.srcip) && 
            this.srcport.equals(ref.srcport) &&
            this.dstip.equals(ref.dstip) &&
            this.dstport.equals(ref.dstport) &&
            this.proto.equals(ref.proto);
    }
 
    @Override
    public int hashCode() {
        return srcip.hashCode() ^ srcport.hashCode() ^ dstip.hashCode() ^ dstport.hashCode() ^ proto.hashCode();
    }

    public AttackKey toAttackKey(){
        return new AttackKey(srcip, dstip, dstport);
    }
 
 }