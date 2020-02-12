def database_connection_string(database):
    if database.scheme == "h2":
        return "jdbc:h2:~/data"
    elif database.scheme == "postgres":
        return "jdbc:postgresql://{}:{}/{}".format(
            database.address,
            database.port,
            database.name)
    else:
        return ""
    end
end
