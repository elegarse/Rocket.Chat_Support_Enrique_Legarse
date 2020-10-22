function module(s,n,t){t.export({mapBusinessHoursForm:()=>i});const i=(s,n)=>{var t;const{daysOpen:i,daysTime:r}=s;return null===(t=n.workHours)||void 0===t?void 0:t.map(s=>{const{day:n,start:{time:t},finish:{time:o}}=s,e=i.includes(n);if(r[n]){const{start:s,finish:t}=r[n];return{day:n,start:s,finish:t,open:e}}return{day:n,start:t,finish:o,open:e}})}}

