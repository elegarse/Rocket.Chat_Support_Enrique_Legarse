function module(e,n,t){let s,c,i;t.export({useHasLicense:()=>l}),t.link("react",{useState(e){s=e},useEffect(e){c=e}},0),t.link("../../app/license/client",{hasLicense(e){i=e}},1);const l=e=>{const[n,t]=s("loading");return c(()=>{i(e).then(e=>{if(e)return t(!0);t(!1)})},[e]),n}}

