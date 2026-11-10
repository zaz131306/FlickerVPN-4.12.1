// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import dev.flicker.vpn.databinding.ItemServerBinding

/**
 * ServerAdapter — список серверов: флаг, имя, хост:порт, протокол,
 * задержка, статус (жив/мёртв/не проверен), выделение выбранного.
 * v4.12.1: ListAdapter + DiffUtil (без мерцания) и текстовый фильтр.
 */
class ServerAdapter(
    private val onClick: (Repository.ServerRow) -> Unit,
    private val onLongClick: (Repository.ServerRow) -> Unit
) : ListAdapter<Repository.ServerRow, ServerAdapter.Holder>(DIFF) {

    companion object {
        private val DIFF = object : DiffUtil.ItemCallback<Repository.ServerRow>() {
            override fun areItemsTheSame(a: Repository.ServerRow, b: Repository.ServerRow) = a.id == b.id
            override fun areContentsTheSame(a: Repository.ServerRow, b: Repository.ServerRow) = a == b
        }
    }

    private var full: List<Repository.ServerRow> = emptyList()
    private var query: String = ""
    var selectedId: String? = null
        private set
    private var checkingIds: Set<String> = emptySet()

    /** Полный список + текущие выбор/проверка. Фильтр применяется заново. */
    fun submit(list: List<Repository.ServerRow>, selected: String?, checking: Set<String> = checkingIds) {
        full = list
        selectedId = selected
        checkingIds = checking
        submitList(applyFilter(full))
    }

    /** Поиск: по имени, хосту, протоколу. Пустой запрос — весь список. */
    fun filter(q: String) {
        query = q.trim()
        submitList(applyFilter(full))
    }

    private fun applyFilter(list: List<Repository.ServerRow>): List<Repository.ServerRow> {
        if (query.isEmpty()) return list
        val q = query.lowercase()
        return list.filter {
            it.name.lowercase().contains(q) ||
                it.host.lowercase().contains(q) ||
                it.protocolLabel.lowercase().contains(q)
        }
    }

    /** Точечное обновление только изменившихся строк (без мерцания списка). */
    fun setChecking(ids: Set<String>) {
        val changed = (checkingIds + ids).filter { (it in checkingIds) != (it in ids) }
        checkingIds = ids
        changed.forEach { id ->
            val pos = currentList.indexOfFirst { it.id == id }
            if (pos >= 0) notifyItemChanged(pos)
        }
    }

    inner class Holder(val binding: ItemServerBinding) : RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val binding = ItemServerBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return Holder(binding)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val row = getItem(position)
        val b = holder.binding
        val ctx = b.root.context

        b.flag.text = row.flag
        b.name.text = row.name
        val sub = buildString {
            append(row.host)
            if (row.port > 0) append(":").append(row.port)
            append(" · ").append(row.protocolLabel)
            if (row.demo) append(" · демо")
        }
        b.subtitle.text = sub

        when {
            checkingIds.contains(row.id) -> {
                b.ping.text = "…"
                b.ping.setTextColor(ctx.getColor(R.color.warn))
                b.dot.setBackgroundResource(R.drawable.dot_warn)
            }
            row.alive == 1 -> {
                b.ping.text = if (row.ping != null && row.ping >= 0) "${row.ping} ms" else "жив"
                b.ping.setTextColor(ctx.getColor(R.color.ok))
                b.dot.setBackgroundResource(R.drawable.dot_ok)
            }
            row.alive == 0 -> {
                b.ping.text = "мёртв"
                b.ping.setTextColor(ctx.getColor(R.color.dead))
                b.dot.setBackgroundResource(R.drawable.dot_dead)
            }
            else -> {
                b.ping.text = "—"
                b.ping.setTextColor(ctx.getColor(R.color.muted))
                b.dot.setBackgroundResource(R.drawable.dot_unknown)
            }
        }

        val selected = row.id == selectedId
        b.root.setBackgroundResource(
            if (selected) R.drawable.item_selected else R.drawable.item_normal
        )
        b.root.setOnClickListener { onClick(row) }
        b.root.setOnLongClickListener {
            onLongClick(row)
            true
        }
    }
}
