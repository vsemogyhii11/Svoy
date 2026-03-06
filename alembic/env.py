from logging.config import fileConfig

from sqlalchemy import pool, MetaData, Column, Integer, String, Float, Text, DateTime, Index
from sqlalchemy.engine import connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# this is the Alembic Config object
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Alembic Config object
config = context.config

# Metadata for autogenerate support
target_metadata = MetaData()

# Define tables schema for Alembic autogenerate
from sqlalchemy import Table

# reports table
reports = Table(
    'reports', target_metadata,
    Column('id', Integer, primary_key=True),
    Column('phone', String, nullable=False),
    Column('type', String, default='scam'),
    Column('description', Text),
    Column('reports_count', Integer, default=1),
    Column('reported_by', Integer),
    Column('first_report', String),
    Column('last_report', String),
    sqlite_autoincrement=True,
)

# checks table
checks = Table(
    'checks', target_metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer, nullable=False),
    Column('message_text', Text),
    Column('risk_score', Float),
    Column('risk_level', String),
    Column('links_found', Integer, default=0),
    Column('phones_found', Integer, default=0),
    Column('has_threat', Integer, default=0),
    Column('checked_at', String),
)

# users table
users = Table(
    'users', target_metadata,
    Column('user_id', Integer, primary_key=True),
    Column('username', String),
    Column('first_name', String),
    Column('checks_count', Integer, default=0),
    Column('reports_count', Integer, default=0),
    Column('first_seen', String),
    Column('last_seen', String),
    Column('language', String, default='ru'),
)

# votes table
votes = Table(
    'votes', target_metadata,
    Column('id', Integer, primary_key=True),
    Column('phone', String, nullable=False),
    Column('user_id', Integer, nullable=False),
    Column('vote', String, nullable=False),
    Column('voted_at', String),
)

# reported_users table
reported_users = Table(
    'reported_users', target_metadata,
    Column('user_id', Integer, primary_key=True),
    Column('username', String),
    Column('first_name', String),
    Column('risk_level', String, default='suspicious'),
    Column('reports', Integer, default=1),
    Column('reported_by', Integer),
    Column('created_at', String),
)

# visited_urls table
visited_urls = Table(
    'visited_urls', target_metadata,
    Column('url', String, primary_key=True),
    Column('visited_at', String),
)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async def run_async_migrations():
        async with connectable.connect() as connection:
            await connection.run_sync(do_run_migrations)

    async def do_run_migrations(connection):
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()

    import asyncio
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
