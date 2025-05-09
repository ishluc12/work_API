exports.up = function (knex) {
    return knex.schema.createTable('users', function (table) {
        table.increments('id').primary();
        table.string('username').notNullable().unique();
        table.text('password').notNullable();
    });
};

exports.down = function (knex) {
    return knex.schema.dropTable('users');
};
