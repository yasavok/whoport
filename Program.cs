using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

const string usage = """
    whoport: кто занял порт на Windows

      whoport             все слушающие порты
      whoport 8080        кто держит порт 8080
      whoport 8080 --kill завершить этот процесс
    """;

var kill = args.Contains("--kill");
var positional = args.Where(arg => !arg.StartsWith('-')).ToArray();

if (args.Contains("--help") || args.Contains("-h"))
{
    Console.WriteLine(usage);
    return 0;
}

int? port = null;
if (positional.Length > 0)
{
    if (!int.TryParse(positional[0], out var parsed) || parsed is < 1 or > 65535)
    {
        Console.Error.WriteLine($"неверный порт: {positional[0]}");
        return 2;
    }
    port = parsed;
}

if (kill && port is null)
{
    Console.Error.WriteLine("--kill работает только с номером порта");
    return 2;
}

var entries = PortTable.Read()
    .Where(entry => port is null || entry.Port == port)
    .OrderBy(entry => entry.Port)
    .ThenBy(entry => entry.Protocol)
    .ToList();

if (entries.Count == 0)
{
    Console.WriteLine(port is null ? "ничего не слушает" : $"порт {port} свободен");
    return 1;
}

Console.WriteLine($"{"порт",-7}{"протокол",-10}{"адрес",-18}{"pid",-8}процесс");
foreach (var entry in entries)
{
    Console.WriteLine($"{entry.Port,-7}{entry.Protocol,-10}{entry.Address,-18}{entry.Pid,-8}{ProcessName(entry.Pid)}");
}

if (!kill)
{
    return 0;
}

var exitCode = 0;
foreach (var pid in entries.Select(entry => entry.Pid).Distinct())
{
    try
    {
        using var process = Process.GetProcessById(pid);
        var name = process.ProcessName;
        process.Kill();
        process.WaitForExit(3000);
        Console.WriteLine($"завершён {name} ({pid})");
    }
    catch (Exception error) when (error is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
    {
        Console.Error.WriteLine($"не удалось завершить {pid}: {error.Message}");
        exitCode = 3;
    }
}
return exitCode;

static string ProcessName(int pid)
{
    if (pid == 0) return "System Idle";
    if (pid == 4) return "System";
    try
    {
        using var process = Process.GetProcessById(pid);
        return process.ProcessName;
    }
    catch (ArgumentException)
    {
        return "?";
    }
}

record PortEntry(int Port, string Protocol, string Address, int Pid);

static class PortTable
{
    const int AfInet = 2;
    const int AfInet6 = 23;
    const int TcpTableOwnerPidListener = 3;
    const int UdpTableOwnerPid = 1;
    const uint ErrorInsufficientBuffer = 122;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, int reserved);

    delegate uint TableReader(IntPtr table, ref int size);

    public static IEnumerable<PortEntry> Read()
    {
        var entries = new List<PortEntry>();

        // Размеры строк и смещения полей взяты из MIB_*ROW_OWNER_PID в iphlpapi.
        ReadRows(
            (IntPtr table, ref int size) => GetExtendedTcpTable(table, ref size, false, AfInet, TcpTableOwnerPidListener, 0),
            24, row => entries.Add(new PortEntry(PortAt(row, 8), "TCP", V4At(row, 4), Marshal.ReadInt32(row, 20))));
        ReadRows(
            (IntPtr table, ref int size) => GetExtendedTcpTable(table, ref size, false, AfInet6, TcpTableOwnerPidListener, 0),
            56, row => entries.Add(new PortEntry(PortAt(row, 20), "TCP6", V6At(row, 0), Marshal.ReadInt32(row, 52))));
        ReadRows(
            (IntPtr table, ref int size) => GetExtendedUdpTable(table, ref size, false, AfInet, UdpTableOwnerPid, 0),
            12, row => entries.Add(new PortEntry(PortAt(row, 4), "UDP", V4At(row, 0), Marshal.ReadInt32(row, 8))));
        ReadRows(
            (IntPtr table, ref int size) => GetExtendedUdpTable(table, ref size, false, AfInet6, UdpTableOwnerPid, 0),
            28, row => entries.Add(new PortEntry(PortAt(row, 20), "UDP6", V6At(row, 0), Marshal.ReadInt32(row, 24))));

        return entries;
    }

    static void ReadRows(TableReader reader, int rowSize, Action<IntPtr> onRow)
    {
        var size = 0;
        if (reader(IntPtr.Zero, ref size) != ErrorInsufficientBuffer)
        {
            return;
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (reader(buffer, ref size) != 0)
            {
                return;
            }
            var count = Marshal.ReadInt32(buffer);
            for (var index = 0; index < count; index++)
            {
                onRow(buffer + 4 + index * rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    static int PortAt(IntPtr row, int offset)
    {
        var high = Marshal.ReadByte(row, offset);
        var low = Marshal.ReadByte(row, offset + 1);
        return (high << 8) | low;
    }

    static string V4At(IntPtr row, int offset)
    {
        var bytes = new byte[4];
        Marshal.Copy(row + offset, bytes, 0, 4);
        return new IPAddress(bytes).ToString();
    }

    static string V6At(IntPtr row, int offset)
    {
        var bytes = new byte[16];
        Marshal.Copy(row + offset, bytes, 0, 16);
        return new IPAddress(bytes).ToString();
    }
}
