const { ApolloServer } = require("@apollo/server");
const depthLimit = require("graphql-depth-limit");

const server = new ApolloServer({ schema, introspection: true, validationRules: [depthLimit(8)] });
