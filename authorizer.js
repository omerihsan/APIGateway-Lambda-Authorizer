const jwt = require('jsonwebtoken');

module.exports.handler = async (event, context, callback) => {

    if (!event.authorizationToken) {
        return callback('Token not found');
    }

    const tokenSplit = event.authorizationToken.split(' ');
    const token = tokenSplit[1];
    if (!(tokenSplit[0].toLowerCase() === 'bearer' && token)) {
        return callback('Token not found');
    }

    jwt.verify(token, process.env.JWT_TOKEN_SECRET, {}, (err, decodedToken) => {
        if (err) {
            return callback('Invalid Token');
        }
        return callback(null, generatePolicy(decodedToken.user, 'Allow', '*'));
    });

};


const generatePolicy = (principalId, effect, resource) => {
    const response = {};
    response.principalId = principalId;
    if (effect && resource) {
        const policyDocument = {};
        policyDocument.Version = '2012-10-17';
        policyDocument.Statement = [];
        const statementOne = {};
        statementOne.Action = 'execute-api:Invoke';
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        response.policyDocument = policyDocument;
    }
    return response;
};
