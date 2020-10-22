function module(e,t,n){let l,a,s,c,r,o,m,i,u,d,E,g,h,C,f,p,y,_;n.export({TableSection:()=>b}),n.link("@rocket.chat/fuselage",{Box(e){l=e},Icon(e){a=e},Margins(e){s=e},Pagination(e){c=e},Select(e){r=e},Skeleton(e){o=e},Table(e){m=e},Tile(e){i=e}},0),n.link("moment",{default(e){u=e}},1),n.link("react",{default(e){d=e},useMemo(e){E=e},useState(e){g=e}},2),n.link("../../../../../../client/contexts/TranslationContext",{useTranslation(e){h=e}},3),n.link("../../../../../../client/hooks/useEndpointData",{useEndpointData(e){C=e}},4),n.link("../../../../../../client/components/data/Growth",{default(e){f=e}},5),n.link("../Section",{Section(e){p=e}},6),n.link("../../../../../../client/components/basic/Buttons/ActionButton",{ActionButton(e){y=e}},7),n.link("../../../../../../client/lib/saveFile",{saveFile(e){_=e}},8);const k=e=>"// type, name, messagesCount, updatedAt, createdAt\n".concat(e.map(e=>{let{createdAt:t,messagesCount:n,name:l,t:a,updatedAt:s}=e;return"".concat(a,", ").concat(l,", ").concat(n,", ").concat(s,", ").concat(t)}).join("\n"));function b(){const e=h(),t=E(()=>[["last 7 days",e("Last_7_days")],["last 30 days",e("Last_30_days")],["last 90 days",e("Last_90_days")]],[e]),[n,b]=g("last 7 days"),w=E(()=>{switch(n){case"last 7 days":return{start:u().set({hour:0,minute:0,second:0,millisecond:0}).subtract(7,"days"),end:u().set({hour:0,minute:0,second:0,millisecond:0}).subtract(1)};case"last 30 days":return{start:u().set({hour:0,minute:0,second:0,millisecond:0}).subtract(30,"days"),end:u().set({hour:0,minute:0,second:0,millisecond:0}).subtract(1)};case"last 90 days":return{start:u().set({hour:0,minute:0,second:0,millisecond:0}).subtract(90,"days"),end:u().set({hour:0,minute:0,second:0,millisecond:0}).subtract(1)}}},[n]),S=e=>b(e),[A,L]=g(0),[P,x]=g(25),I=E(()=>({start:w.start.toISOString(),end:w.end.toISOString(),offset:A,count:P}),[w,A,P]),v=C("engagement-dashboard/channels/list",I),B=E(()=>{if(v)return v.channels.map(e=>{let{room:{t:t,name:n,usernames:l,ts:a,_updatedAt:s},messages:c,diffFromLastWeek:r}=e;return{t:t,name:n||l.join(" × "),createdAt:a,updatedAt:s,messagesCount:c,messagesVariation:r}})},[v]),T=()=>{_(k(B),"Channels_start_".concat(I.start,"_end_").concat(I.end,".csv"))};return d.createElement(p,{filter:d.createElement(d.Fragment,null,d.createElement(r,{options:t,value:n,onChange:S}),d.createElement(y,{mis:"x16",disabled:!B,onClick:T,"aria-label":e("Download_Info"),icon:"download"}))},d.createElement(l,null,B&&!B.length&&d.createElement(i,{fontScale:"p1",color:"info",style:{textAlign:"center"}},e("No_data_found")),(!B||B.length)&&d.createElement(m,null,d.createElement(m.Head,null,d.createElement(m.Row,null,d.createElement(m.Cell,null,"#"),d.createElement(m.Cell,null,e("Channel")),d.createElement(m.Cell,null,e("Created")),d.createElement(m.Cell,null,e("Last_active")),d.createElement(m.Cell,null,e("Messages_sent")))),d.createElement(m.Body,null,B&&B.map((e,t)=>{let{t:n,name:l,createdAt:c,updatedAt:r,messagesCount:o,messagesVariation:i}=e;return(d.createElement(m.Row,{key:t},d.createElement(m.Cell,null,t+1,"."),d.createElement(m.Cell,null,d.createElement(s,{inlineEnd:"x4"},"d"===n&&d.createElement(a,{name:"at"})||"c"===n&&d.createElement(a,{name:"lock"})||"p"===n&&d.createElement(a,{name:"hashtag"})),l),d.createElement(m.Cell,null,u(c).format("L")),d.createElement(m.Cell,null,u(r).format("L")),d.createElement(m.Cell,null,o," ",d.createElement(f,null,i))))}),!B&&Array.from({length:5},(e,t)=>d.createElement(m.Row,{key:t},d.createElement(m.Cell,null,d.createElement(o,{width:"100%"})),d.createElement(m.Cell,null,d.createElement(o,{width:"100%"})),d.createElement(m.Cell,null,d.createElement(o,{width:"100%"})),d.createElement(m.Cell,null,d.createElement(o,{width:"100%"})),d.createElement(m.Cell,null,d.createElement(o,{width:"100%"})))))),d.createElement(c,{current:A,itemsPerPage:P,itemsPerPageLabel:()=>e("Items_per_page:"),showingResultsLabel:t=>{let{count:n,current:l,itemsPerPage:a}=t;return e("Showing results %s - %s of %s",l+1,Math.min(l+a,n),n)},count:v&&v.total||0,onSetItemsPerPage:x,onSetCurrent:L})))}}

