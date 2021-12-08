var OAuthLogin = (props) => {
    if(location.hash) {
        const hash = window.location.hash.substring(1);
        console.log(hash)
        const params = hash.split('&').reduce(function (res, item) {
            var parts = item.split('=');
            res[parts[0]] = parts[1];
            return res;
        }, {});
        console.log("The access token value is " + params);
        console.log("STORAGE: " + window.sessionStorage.getItem('state'))
        if(params.access_token && params.state == window.sessionStorage.getItem('state')) {
            var jwtToken = jwt.parseJwtToken(params.access_token);
            jwt.storeJwtToken(params.access_token);
            props.dispatch({
                type: 'login',
                user: jwtToken.user_name,
                authorities: jwtToken.authorities,
                token: params.access_token
            });
            return (<ReactRouterDOM.Redirect to="/"/>);
        }
    }
    alerts.error('Access denied!');
    return (<ReactRouterDOM.Redirect to="/login"/>);
};
OAuthLogin = ReactRedux.connect()(OAuthLogin);

