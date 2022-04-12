//------------------------------------------------------------------------------
// <auto-generated />
// This file was automatically generated by the UpdateVendors tool.
//------------------------------------------------------------------------------
#pragma warning disable CS0618, CS0649, CS1574, CS1580, CS1581, CS1584, SYSLIB0011,SYSLIB0032
// dnlib: See LICENSE.txt for more info

using Datadog.Trace.Vendors.dnlib.IO;

namespace Datadog.Trace.Vendors.dnlib.DotNet.MD {
	/// <summary>
	/// #Pdb stream
	/// </summary>
	internal sealed class PdbStream : HeapStream {
		/// <summary>
		/// Gets the PDB id
		/// </summary>
		public byte[] Id { get; private set; }

		/// <summary>
		/// Gets the entry point token or 0
		/// </summary>
		public MDToken EntryPoint { get; private set; }

		/// <summary>
		/// Gets the referenced type system tables in the PE metadata file
		/// </summary>
		public ulong ReferencedTypeSystemTables { get; private set; }

		/// <summary>
		/// Gets all type system table rows. This array has exactly 64 elements.
		/// </summary>
		public uint[] TypeSystemTableRows { get; private set; }

		/// <inheritdoc/>
		public PdbStream(DataReaderFactory mdReaderFactory, uint metadataBaseOffset, StreamHeader streamHeader)
			: base(mdReaderFactory, metadataBaseOffset, streamHeader) {
			var reader = CreateReader();
			Id = reader.ReadBytes(20);
			EntryPoint = new MDToken(reader.ReadUInt32());
			var tables = reader.ReadUInt64();
			ReferencedTypeSystemTables = tables;
			var rows = new uint[64];
			for (int i = 0; i < rows.Length; i++, tables >>= 1) {
				if (((uint)tables & 1) != 0)
					rows[i] = reader.ReadUInt32();
			}
			TypeSystemTableRows = rows;
		}
	}
}
