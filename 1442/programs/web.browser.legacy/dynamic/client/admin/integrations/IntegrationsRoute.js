function module(n,t,e){var i,o,a,u,l,r,c,g,f;function s(){var n=a(o((function(){return["manage-incoming-integrations","manage-outgoing-integrations","manage-own-incoming-integrations","manage-own-outgoing-integrations"]}),[])),t=u("context");return n?"new"===t?i.createElement(c,null):"edit"===t?i.createElement(g,null):"history"===t?i.createElement(f,null):i.createElement(r,null):i.createElement(l,null)}e.link("react",{default:function(n){i=n},useMemo:function(n){o=n}},0),e.link("../../contexts/AuthorizationContext",{useAtLeastOnePermission:function(n){a=n}},1),e.link("../../contexts/RouterContext",{useRouteParameter:function(n){u=n}},2),e.link("../../components/NotAuthorizedPage",{default:function(n){l=n}},3),e.link("./IntegrationsPage",{default:function(n){r=n}},4),e.link("./new/NewIntegrationsPage",{default:function(n){c=n}},5),e.link("./edit/EditIntegrationsPage",{default:function(n){g=n}},6),e.link("./edit/OutgoingWebhookHistoryPage",{default:function(n){f=n}},7),e.exportDefault(s)}

