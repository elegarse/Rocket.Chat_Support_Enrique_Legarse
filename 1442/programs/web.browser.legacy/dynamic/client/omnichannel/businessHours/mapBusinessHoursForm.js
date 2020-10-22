function module(n,r,i){i.export({mapBusinessHoursForm:function(){return t}});var t=function(n,r){var i,t=n.daysOpen,s=n.daysTime;return null===(i=r.workHours)||void 0===i?void 0:i.map((function(n){var r=n.day,i=n.start.time,a=n.finish.time,e=t.includes(r);if(s[r]){var o=s[r],u,d;return{day:r,start:o.start,finish:o.finish,open:e}}return{day:r,start:i,finish:a,open:e}}))}}

