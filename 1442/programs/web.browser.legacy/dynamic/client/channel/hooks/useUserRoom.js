function module(n,e,u){var i,o,t;u.export({useUserRoom:function(){return c}}),u.link("react",{useCallback:function(n){i=n}},0),u.link("../../hooks/useReactiveValue",{useReactiveValue:function(n){o=n}},1),u.link("../../../app/models/client",{Rooms:function(n){t=n}},2);var c=function(n,e){return o(i((function(){return t.findOne({_id:n},{fields:e})}),[n,e]))}}

