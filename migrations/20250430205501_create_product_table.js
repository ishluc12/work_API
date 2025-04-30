exports.up = function (knex) {
    return knex.schema.createTable('product', function (table) {
        table.increments('product_id').primary();
        table.string('product_name').notNullable();
        table.text('description');
        table.integer('quantity').notNullable().defaultTo(0);
        table.decimal('price', 10, 2).notNullable();
        table.timestamp('currentstamp').defaultTo(knex.fn.now());
    });
};

exports.down = function (knex) {
    return knex.schema.dropTable('product');
};
