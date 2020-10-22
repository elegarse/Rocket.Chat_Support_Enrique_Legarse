function module(e,t,n){let l,o,a,u;n.link("react",{default(e){l=e}},0),n.link("../../contexts/AuthorizationContext",{useRole(e){o=e}},1),n.link("../../components/NotAuthorizedPage",{default(e){a=e}},2),n.link("./FederationDashboardPage",{default(e){u=e}},3);const i=()=>{const e=o("admin");return e?l.createElement(u,null):l.createElement(a,null)};n.exportDefault(i)}

