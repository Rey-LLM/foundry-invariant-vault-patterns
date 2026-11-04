const { ApolloServer } = require("@apollo/server");
const depthLimit = require("graphql-depth-limit");

const server = new ApolloServer({ schema, introspection: process.env.NODE_ENV !== "production", validationRules: [depthLimit(8)] });
