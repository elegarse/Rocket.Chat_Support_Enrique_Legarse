function module(e,t,n){let l,a,o,c,i,r,u,E,d,m;n.link("react",{default(e){l=e}},0),n.link("@rocket.chat/fuselage",{Box(e){a=e},Accordion(e){o=e}},1),n.link("../../contexts/TranslationContext",{useTranslation(e){c=e}},2),n.link("../../contexts/SettingsContext",{useSetting(e){i=e}},3),n.link("../../components/basic/Page",{default(e){r=e}},4),n.link("../../components/NotAuthorizedPage",{default(e){u=e}},5),n.link("./TwoFactorTOTP",{default(e){E=e}},6),n.link("./TwoFactorEmail",{default(e){d=e}},7),n.link("./EndToEnd",{default(e){m=e}},8);const s=()=>{const e=c(),t=i("Accounts_TwoFactorAuthentication_Enabled"),n=i("Accounts_TwoFactorAuthentication_By_Email_Enabled"),s=i("E2E_Enable");return t||s?l.createElement(r,null,l.createElement(r.Header,{title:e("Security")}),l.createElement(r.ScrollableContentWithShadow,null,l.createElement(a,{maxWidth:"x600",w:"full",alignSelf:"center"},l.createElement(o,null,(t||n)&&l.createElement(o.Item,{title:e("Two Factor Authentication"),defaultExpanded:!0},t&&l.createElement(E,null),n&&l.createElement(d,null)),s&&l.createElement(o.Item,{title:e("E2E Encryption"),defaultExpanded:!t},l.createElement(m,null)))))):l.createElement(u,null)};n.exportDefault(s)}

