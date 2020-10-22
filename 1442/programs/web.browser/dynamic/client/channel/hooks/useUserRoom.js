function module(e,l,o){let i,s,n;o.export({useUserRoom:()=>a}),o.link("react",{useCallback(e){i=e}},0),o.link("../../hooks/useReactiveValue",{useReactiveValue(e){s=e}},1),o.link("../../../app/models/client",{Rooms(e){n=e}},2);const a=(e,l)=>s(i(()=>n.findOne({_id:e},{fields:l}),[e,l]))}

