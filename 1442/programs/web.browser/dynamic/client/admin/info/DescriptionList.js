function module(e,l,t){let n,r,i,a,o;t.link("@babel/runtime/helpers/extends",{default(e){n=e}},0),t.link("@babel/runtime/helpers/objectWithoutProperties",{default(e){r=e}},1),t.export({DescriptionList:()=>d}),t.link("@rocket.chat/fuselage",{Box(e){i=e},Table(e){a=e}},0),t.link("react",{default(e){o=e}},1);const c={wordBreak:"break-word"},d=o.memo(e=>{let{children:l,title:t}=e,c=r(e,["children","title"]);return(o.createElement(o.Fragment,null,t&&o.createElement(i,{display:"flex",justifyContent:"flex-end",width:"30%",paddingInline:"x8"},t),o.createElement(a,n({striped:!0,marginBlockEnd:"x32",width:"full"},c),o.createElement(a.Body,null,l))))}),u=e=>{let{children:l,label:t}=e,n=r(e,["children","label"]);return(o.createElement(a.Row,n,o.createElement(a.Cell,{is:"th",scope:"col",width:"30%",align:"end",color:"hint",backgroundColor:"surface",fontScale:"p2",style:c},t),o.createElement(a.Cell,{width:"70%",align:"start",color:"default",style:c},l)))};d.Entry=o.memo(u)}

